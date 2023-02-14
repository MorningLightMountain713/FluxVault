from dataclasses import dataclass, field
from pathlib import Path

import yaml

from fluxvault.fs import ConcreteFsEntry, FsEntryStateManager, FsStateManager, FsType
from fluxvault.helpers import RemoteStateDirective, SyncStrategy
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

            for dir in state.get("dirs", [])[::-1]:
                # LIFO
                log.info(f"Removing dir: {dir}")
                Path(dir).rmdir()

            state_file.unlink()

    def build_catalogue(self, app_root):
        """Builds catalogue for specific component, called by parent `FluxApp`"""

        # Break down. Esp the folder creation thing - DRY

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

        ConcreteFsEntry.log_objects_in_dir(fake_root)

        entries = ConcreteFsEntry.entries_in_dir(staging_dir)

        created_dirs = []
        created_symlinks = []

        for group in self.member_of:
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
                        remote_path = (
                            self.remote_workdir / directive.remote_dir / path.name
                        )

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

        # do common first so component overwrites if conflict? (specificity)
        # doesn't seem very efficient. Does it even work?
        for path in entries:
            # default
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
            # fake_path.parent.mkdir(parents=True, exist_ok=True)

            if not fake_path.exists():
                fake_path.symlink_to(path)
                created_symlinks.append(str(fake_path))

        root_tree = ConcreteFsEntry.build_tree(fake_root)
        root_tree.realize()

        log.info("File tree:\n")
        print(root_tree)
        print()

        for fs_object in root_tree.recurse():
            if fs_object.path.name == "fake_root":
                continue

            remote_absolute_path = "/" / fs_object.path.relative_to(fake_root)
            directive = self.state_manager.get_directive_by_remote_path(
                remote_absolute_path
            )

            if not directive:
                # add fs_object.name here??
                directive = RemoteStateDirective(remote_dir=remote_absolute_path.parent)

            managed_object = FsEntryStateManager(
                name=fs_object.path.name,
                remit=directive,
                local_parent=fs_object.path.parent,
                remote_workdir=self.remote_workdir,
                concrete_fs=fs_object,
            )
            self.state_manager.add_object(managed_object)

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
    # polling_interval: int = 900
    # run_once: bool = False
    root_dir: Path = field(default_factory=Path)
    fluxnode_ips: list[str] = field(default_factory=list)
    # state_manager: FsStateManager = field(default_factory=FsStateManager)

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
            component.build_catalogue(self.root_dir)
