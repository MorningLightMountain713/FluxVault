from dataclasses import dataclass, field
from pathlib import Path

import yaml
from rich.pretty import pprint

from fluxvault.fs import ConcreteFsEntry, FsEntryStateManager, FsStateManager, FsType
from fluxvault.helpers import AppMode, RemoteStateDirective, SyncStrategy
from fluxvault.log import log


@dataclass
class FluxTask:
    name: str
    params: list


## Flow
# Collection of RemoteStateDirective created in CLI. Covers both files
# and folders. Controls how files in physical dirs are synced
# Fs created from fake_root
# loop through local files, match to a statedirective.
# If found, follow that, create RemoteFsEntry and create a ConcreteFs entry and slot it in the tree,
# otherwise slot in tree at local_parent (workdir)
# state directives are attached to RemoteFsEntry.
# EVERY FILE IN FAKE ROOT TURNS INTO A RemoteFsEntry
# loop through unfound stateDirectives and match in fake_root. Update RemoteFsEntry
# Once state has been matched, realize? Then validate?


@dataclass
class FluxComponent:
    name: str
    state_manager: FsStateManager = field(default_factory=FsStateManager)
    tasks: list[FluxTask] | None = None
    # root_dir: Path | None = None
    local_workdir: Path | None = None
    remote_workdir: Path = Path("/tmp")
    member_of: set[str] = field(default_factory=set)

    def add_groups(self, groups: list[str]):
        self.member_of = self.member_of.union(set(groups))

    def update_paths(self, dir: Path):
        # mixing in remote path here
        self.local_workdir = dir
        self.state_manager.update_paths(self.local_workdir, self.remote_workdir)

    def validate_local_objects(self):
        self.state_manager.validate_local_objects()

    def add_directives(self, directives: list[RemoteStateDirective]):
        self.state_manager.add_directives(directives)

    def add_tasks(self, tasks: list):
        for task in tasks:
            self.add_task(task)

    def add_task(self, task: FluxTask):
        self.tasks.append(task)

    def get_task(self, name) -> FluxTask:
        for task in self.tasks:
            if task.name == name:
                return task

    def remove_catalogue(self):
        state_file: Path = self.local_workdir / ".fake_root_state"

        if state_file.is_file():
            with open(state_file, "r") as stream:
                state: dict = yaml.safe_load(stream.read())

            for link in state.get("symlinks", []):
                log.info(f"Unlinking: {link}")
                Path(link).unlink()

            state_file.unlink()

            for dir in state.get("dirs", [])[::-1]:
                # LIFO
                log.info(f"Removing dir: {dir}")
                Path(dir).rmdir()

    def symlink_group(self, group, groups_dir, app_root, fake_root) -> tuple:
        created_dirs = []
        created_symlinks = []

        group_dir = groups_dir / group
        group_dir.mkdir(parents=True, exist_ok=True)

        group_entries = ConcreteFsEntry.entries_in_dir(group_dir)

        for path in group_entries:
            remote_path: Path = self.remote_workdir / path.name

            directive = self.state_manager.get_directive_by_path(
                path.relative_to(app_root)
            )

            if directive:
                if directive.remote_dir.is_absolute():
                    remote_path = directive.remote_dir / path.name
                elif directive.remote_dir:
                    remote_path = self.remote_workdir / directive.remote_dir / path.name

            remote_relative = remote_path.relative_to("/")
            parent_parts = remote_relative.parent.parts

            previous = None
            for dir in parent_parts:
                if not previous:
                    next_dir = fake_root / dir
                else:
                    next_dir = previous / dir
                if not next_dir.is_dir():
                    # will throw if file exists with same name
                    next_dir.mkdir()
                    created_dirs.append(str(next_dir))
                previous = next_dir

            fake_path = fake_root / remote_relative

            if not fake_path.exists():
                fake_path.symlink_to(path)
                created_symlinks.append(str(fake_path))
        return created_dirs, created_symlinks

    def symlink_path(self, path: Path, app_root, fake_root) -> tuple:
        created_dirs = []
        created_symlinks = []

        # default
        remote_path: Path = self.remote_workdir / path.name

        directive = self.state_manager.get_directive_by_path(path.relative_to(app_root))

        if directive:
            if directive.remote_dir.is_absolute():
                remote_path = directive.remote_dir / path.name
            elif directive.remote_dir:
                remote_path = self.remote_workdir / directive.remote_dir / path.name

        remote_relative = remote_path.relative_to("/")
        parent_parts = remote_relative.parent.parts

        previous = None
        for dir in parent_parts:
            if not previous:
                next_dir = fake_root / dir
            else:
                next_dir = previous / dir
            if not next_dir.is_dir():
                # will throw if file exists with same name
                next_dir.mkdir()
                created_dirs.append(str(next_dir))
            previous = next_dir

        fake_path = fake_root / remote_relative
        # fake_path.parent.mkdir(parents=True, exist_ok=True)

        if not fake_path.exists():
            fake_path.symlink_to(path)
            created_symlinks.append(str(fake_path))

        return created_dirs, created_symlinks

    def build_fs(
        self,
        app_mode: AppMode,
        fileserver_dir: Path,
        tree_root: Path,
        remote_prefix: Path = Path("/"),
    ):
        root_tree = ConcreteFsEntry.build_tree(tree_root)
        root_tree.realize()

        log.info("File tree:\n")
        print(root_tree)
        print()

        for fs_object in root_tree.recurse():
            # if fs_object.path.name == tree_root.name:
            if fs_object.path.name == "fake_root":
                continue

            remote_absolute_path = remote_prefix / fs_object.path.relative_to(tree_root)
            directive = self.state_manager.get_directive_by_remote_path(
                remote_absolute_path
            )

            if not directive:
                # Default directive
                if (
                    app_mode == AppMode.FILESERVER
                    and remote_absolute_path.is_relative_to(self.remote_workdir)
                ):
                    sync_strategy = SyncStrategy.STRICT
                else:
                    sync_strategy = SyncStrategy.ENSURE_CREATED

                directive = RemoteStateDirective(
                    remote_dir=remote_absolute_path.parent, sync_strategy=sync_strategy
                )

            # this should only happen with fileserver root
            # root_name = ""
            # if fs_object.path.name == tree_root.name:
            #     root_name = self.remote_workdir.name

            managed_object = FsEntryStateManager(
                name=fs_object.path.name,
                remit=directive,
                local_parent=fs_object.path.parent,
                remote_workdir=self.remote_workdir,
                concrete_fs=fs_object,
                # root_name=root_name,
            )
            self.state_manager.add_object(managed_object)

    def build_catalogue(self, app_mode: AppMode, fileserver_dir: Path, app_root: Path):
        """Builds catalogue for specific component, called by parent `FluxApp`"""

        fake_root: Path = self.local_workdir / "fake_root"
        staging_dir: Path = self.local_workdir / "staging"
        groups_dir: Path = app_root / "groups"

        fake_root.mkdir(parents=True, exist_ok=True)
        staging_dir.mkdir(parents=True, exist_ok=True)
        groups_dir.mkdir(parents=True, exist_ok=True)

        files_in_root = ConcreteFsEntry.are_files_in_dir(fake_root)

        if files_in_root:
            raise ValueError(
                "Files at top level not allowed in fake_root, use a directory (remember to check for hidden files"
            )

        state_file: Path = self.local_workdir / ".fake_root_state"
        # we crashed, or system did etc
        if state_file.is_file():
            self.remove_catalogue()

        created_dirs = []
        created_symlinks = []

        if app_mode == AppMode.FILESERVER:
            entries = ConcreteFsEntry.entries_in_dir(fileserver_dir)
            for entry in entries:
                fake_path = staging_dir / entry.name
                fake_path.symlink_to(entry)
                created_symlinks.append(str(fake_path))
            # leave clean state
            app_dirs = [
                app_root,
                self.local_workdir.parent,
                self.local_workdir,
                groups_dir,
                groups_dir / "all",
                fake_root,
                staging_dir,
            ]
            app_dirs = [str(x) for x in app_dirs]
            created_dirs.extend(app_dirs)

        ConcreteFsEntry.log_objects_in_dir(fake_root)

        # if app_mode == AppMode.FILESERVER:
        # symlink in vault_dir to staging_dir
        # dirs, sims = self.symlink_path(app, app_root, fake_root)

        entries = ConcreteFsEntry.entries_in_dir(staging_dir)

        for group in self.member_of:
            dirs, sims = self.symlink_group(group, groups_dir, app_root, fake_root)
            created_dirs.extend(dirs)
            created_symlinks.extend(sims)

        # do groups first so component overwrites if conflict? (specificity)
        # doesn't seem very efficient
        for path in entries:
            dirs, sims = self.symlink_path(path, app_root, fake_root)
            created_dirs.extend(dirs)
            created_symlinks.extend(sims)

        self.build_fs(app_mode, fileserver_dir, fake_root)

        with open(self.local_workdir / ".fake_root_state", "w") as stream:
            stream.write(
                yaml.dump({"dirs": created_dirs, "symlinks": created_symlinks})
            )


@dataclass
class FluxApp:
    name: str
    components: list[FluxComponent] = field(default_factory=list)
    comms_port: int = 8888
    sign_connections: bool = False
    signing_key: str = ""
    root_dir: Path = field(default_factory=Path)
    fileserver_dir: Path = field(default_factory=Path)
    fluxnode_ips: list[str] = field(default_factory=list)
    app_mode: AppMode = AppMode.MULTI_COMPONENT

    def add_component(self, component: FluxComponent):
        existing = next(
            filter(lambda x: x.name == component.name, self.components), None
        )
        if existing:
            log.warn(f"Component already exists: {component.name}")
            return

        component.root_dir = self.root_dir / component.name
        self.components.append(component)

    def ensure_included(self, name: str) -> FluxComponent:
        component = next(filter(lambda x: x.name == name, self.components), None)
        if not component:
            component = FluxComponent(name)
            self.add_component(component)

        return component

    def get_component(self, name: str) -> FluxComponent:
        if self.app_mode == AppMode.FILESERVER:
            return self.components[0]

        return next(filter(lambda x: x.name == name, self.components), None)

    def merge_global_into_component(self, component: FluxComponent):
        global_config = self.state_manager.get_all_objects()
        component.state_manager.merge_config(global_config)

    def ensure_removed(self, name: str):
        self.components = [c for c in self.components if c.get("name") != name]

    def update_common_objects(self, files: list[FsEntryStateManager]):
        self.state_manager.add_objects(files)

    def update_paths(self, root_app_dir: Path):
        for component in self.components:
            component.update_paths(root_app_dir / "components" / component.name)
        self.state_manager.update_paths(root_app_dir / "common_files")

    def validate_local_objects(self):
        for component in self.components:
            component.validate_local_objects()

    def serialize(self):
        ...

    def remove_catalogue(self):
        """Deletes all symlinks and dirs created in fake_root"""
        for component in self.components:
            component.remove_catalogue()

    def build_catalogue(self):
        for component in self.components:
            component.build_catalogue(
                self.app_mode, self.fileserver_dir.resolve(), self.root_dir
            )

    # def build_fs(self):
    #     # should only ever be one here? This is for FILESERVER ONLY
    #     for component in self.components:
    #         component.build_fs(self.app_mode, self.fileserver_dir, self.root_dir, component.remote_workdir)
