import binascii
import io
import tarfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from fluxvault.helpers import SyncStrategy, bytes_to_human, size_of_object, tar_object
from fluxvault.log import log


@dataclass
class FluxTask:
    name: str
    params: list


@dataclass
class FileSystemEntry:
    is_dir: bool
    local_path: Path
    fake_root: bool
    is_empty: bool | None = None
    remote_prefix: Path | None = None
    local_workdir: Path | None = None
    remote_workdir: Path | None = None
    local_crc: int = 0
    remote_crc: int = 0
    keeper_context: bool = True
    remote_object_exists: bool = False
    local_object_exists: bool = False
    in_sync: bool = False
    validated_remote_crc: int = 0
    file_data: bytes = b""
    sync_strategy: SyncStrategy = SyncStrategy.STRICT

    # def is_dir(self) -> bool:
    #     return (self.local_workdir / self.local_path).is_dir()

    @property
    def absolute_local_path(self) -> Path:
        return self.local_workdir / self.local_path

    def is_remote_prefix_absolute(self) -> bool:
        return self.remote_prefix.is_absolute() if self.remote_prefix else False

    # def local_absolute_from_remote_absolute(self, path: Path):

    @property
    def absolute_remote_path(self) -> Path:
        expanded_remote = (
            self.remote_prefix / self.local_path
            if self.remote_prefix
            else self.local_path
        )
        return (
            self.remote_workdir / expanded_remote
            if not expanded_remote.is_absolute()
            else expanded_remote
        )

    @property
    def absolute_remote_dir(self) -> Path:
        match self.remote_prefix:
            case x if x and x.is_absolute():
                return x
            case x if x:
                return self.remote_workdir / self.remote_prefix
            case x if not x:
                return self.remote_workdir

        # return (
        #     self.remote_workdir / self.remote_prefix
        #     if self.remote_prefix and not self.remote_prefix.is_absolute()
        #     else self.remote_prefix
        # )

    def is_empty_dir(self) -> bool:
        return not any((self.local_workdir / self.local_path).iterdir())

    def expanded_remote_path(self) -> Path:
        return (
            self.remote_prefix / self.local_path
            if self.remote_prefix
            else self.local_path
        )

    def crc_file(self, filename: Path, crc: int) -> int:
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 128), b""):
                crc = binascii.crc32(chunk, crc)

        return crc

    def crc_directory(self, directory: Path, crc: int) -> int:
        crc = binascii.crc32(directory.name.encode(), crc)
        for path in sorted(directory.iterdir(), key=lambda p: str(p).lower()):
            crc = binascii.crc32(path.name.encode(), crc)

            if path.is_file():
                crc = self.crc_file(path, crc)
            elif path.is_dir():
                crc = self.crc_directory(path, crc)
        return crc

    def get_file_hash(self, file: Path):
        crc = self.crc_file(file, 0)
        return {str(file.relative_to(self.local_workdir)): crc}

    def get_directory_hashes(self, dir: str = "") -> dict[str, int]:
        hashes = {}

        if dir:
            p = Path(dir)
            if not p.is_absolute:
                p = self.local_workdir / self.local_path
        else:
            p = self.local_workdir / self.local_path

        if not p.exists() and p.is_dir():
            return hashes

        crc = binascii.crc32(p.name.encode())

        # this is common format "just relative path"
        hashes.update({str(p.relative_to(self.local_workdir)): crc})
        for path in sorted(p.iterdir(), key=lambda p: str(p).lower()):
            if path.is_dir():
                hashes.update(self.get_directory_hashes(str(path)))

            elif path.is_file():
                hashes.update(self.get_file_hash(path))
        return hashes

    def validate_local_object(self):
        if self.keeper_context:
            if self.local_path.is_absolute():
                raise ValueError("All paths must be relative on Keeper")

        p = self.local_workdir / self.local_path

        if not p.exists():
            # check if object exists in app common dir
            common_path = self.local_workdir.parent / "common_files"
            p_common = common_path / p.name

            if (p_common).exists():
                self.local_workdir = common_path
                log.info(
                    f"Managed object {str(p)} not found locally, using file from common directory"
                )

                p = p_common
                self.local_path = p.relative_to(self.local_workdir)

            else:
                log.error(
                    f"Managed object {str(p)} not found locally or permission error... skipping!"
                )
                return

        self.local_object_exists = True
        if p.is_file():
            if p.stat().st_size == 0:
                self.is_empty = True
            self.local_crc = self.crc_file(p, 0)
        elif p.is_dir():
            self.local_crc = self.crc_directory(p, 0)

    def compare_objects(self) -> dict:
        if not self.local_object_exists:
            return

        path = self.local_path
        if self.remote_prefix:
            path = self.remote_prefix / self.local_path
        if not self.remote_crc:  # remote file crc is 0 if it doesn't exist
            self.remote_object_exists = False
            if self.local_crc:
                log.info(f"Agent needs new object {self.local_path.name}... sending")
                return

        self.remote_object_exists = True

        if self.remote_crc != self.local_crc:
            self.in_sync = False
            if (
                self.validated_remote_crc == self.remote_crc
                and self.local_object_exists
            ):
                log.info(
                    f"Agent remote object {str(path)} is different than local object but has been validated due to sync strategy"
                )
                return

            if self.local_object_exists:
                log.info(
                    f"Agent remote object {str(path)} is different that local object... analyzing further"
                )
                return

        if self.remote_crc == self.local_crc:
            log.info(f"Agent object {str(path)} is up to date... skipping!")
            self.in_sync = True


@dataclass
class FileSystemeGroup:
    managed_objects: list[FileSystemEntry] = field(default_factory=list)
    working_dir: Path = field(default_factory=Path)
    remote_workdir: Path = field(default_factory=Path)
    flattened: bool = False

    def __iter__(self):
        yield from self.managed_objects

    @classmethod
    def filter_hierarchy(
        cls, current_path: Path, existing_paths: list[Path]
    ) -> list[Path]:
        # this needs heavy testing
        for existing_path in existing_paths.copy():
            if current_path.is_relative_to(existing_path):
                # our ancestor is already in the list. We will get replaced
                # when they get synced (don't add ourselves)
                continue

            elif existing_path.is_relative_to(current_path):
                # we are higher up the tree.. remove existing_path and
                # install ourselves
                existing_paths.remove(existing_path)
                existing_paths.append(current_path)

        return existing_paths

    def absolute_remote_dirs(self) -> list[Path]:
        return [x.absolute_remote_path for x in self.managed_objects if x.is_dir]

    def absolute_remote_paths(self) -> list[str]:
        return [str(x.absolute_remote_path) for x in self.managed_objects]

    def merge_config(self, objects):
        for obj in objects:
            if isinstance(obj, FileSystemEntry):
                obj.remote_workdir = self.remote_workdir
                self.managed_objects.append(obj)
            else:
                log.error(
                    f"Object of type {type(obj)} added to file manager, must be `FileSystemEntry`"
                )

    def add_objects(self, objects: list):
        for obj in objects:
            self.add_object(obj)

    def add_object(self, obj: FileSystemEntry):
        if not obj.local_workdir:
            obj.local_workdir = self.working_dir
        self.managed_objects.append(obj)

    def get_object_by_remote_path(self, remote: Path) -> FileSystemEntry:
        for fs_object in self.managed_objects:
            path = fs_object.absolute_remote_path

            if path == remote:
                return fs_object

    def get_all_objects(self) -> list[FileSystemEntry]:
        return self.managed_objects

    def update_paths(self, local: Path, remote: Path | None = None):
        self.working_dir = local
        self.remote_workdir = remote
        for obj in self.managed_objects:
            if not obj.fake_root:
                obj.local_workdir = self.working_dir / "files_only"
                if remote:
                    obj.remote_workdir = remote

    def validate_local_objects(self):
        for obj in self.managed_objects:
            obj.validate_local_object()


@dataclass
class FluxComponentConfig:
    name: str
    file_manager: FileSystemeGroup = field(default_factory=FileSystemeGroup)
    tasks: list[FluxTask] = field(default_factory=list)
    root_dir: Path = field(default_factory=Path)
    local_working_dir: Path = Path()
    remote_working_dir: Path = Path("/tmp")
    directories_built: bool = False

    def update_paths(self, dir: Path):
        # mixing in remote path here
        self.local_working_dir = dir
        self.file_manager.update_paths(self.local_working_dir, self.remote_working_dir)

    def validate_local_objects(self):
        self.file_manager.validate_local_objects()

    def add_tasks(self, tasks: list):
        for task in tasks:
            self.add_task(task)

    def add_task(self, task: FluxTask):
        self.tasks.append(task)

    def get_task(self, name) -> FluxTask:
        for task in self.tasks:
            if task.name == name:
                return task

    # def get_dirs(self) -> list:
    #     return self.file_manager.get_dirs()

    def build_catalogue(self):
        fake_root = self.local_working_dir / "fake_root"

        for f in fake_root.iterdir():
            log.info(f"Root object: {f}")

        fs_objects = fake_root.glob("**/*")

        files_in_root = any(x.is_file() for x in fake_root.iterdir())

        if files_in_root:
            raise ValueError(
                "Files at top level not allowed in fake_root, use a directory (remember to check for hidden files"
            )

        for fs_object in fs_objects:
            is_empty = False
            is_dir = False

            # fake_path = "/" / fs_object.relative_to(fake_root)
            if fs_object.is_dir():
                print("IS_DIR", fs_object)
                is_dir = True
                empty_dir = not any(fs_object.iterdir())
                if empty_dir:
                    is_empty = True

            relative_path = fs_object.relative_to(fake_root)

            managed_object = FileSystemEntry(
                is_dir=is_dir,
                local_path=relative_path,
                fake_root=True,
                is_empty=is_empty,
                # this would be "/" outside testing
                remote_prefix=Path("/tmp/fake_root"),
                local_workdir=fake_root,
            )
            print(managed_object)
            self.file_manager.add_object(managed_object)


@dataclass
class FluxAppConfig:
    name: str
    components: list[FluxComponentConfig] = field(default_factory=list)
    comms_port: int = 8888
    sign_connections: bool = False
    signing_key: str = ""
    polling_interval: int = 900
    run_once: bool = False
    root_dir: Path = field(default_factory=Path)
    agent_ips: list[str] = field(default_factory=list)
    file_manager: FileSystemeGroup = field(default_factory=FileSystemeGroup)

    def add_component(self, component: FluxComponentConfig):
        existing = next(
            filter(lambda x: x.name == component.name, self.components), None
        )
        if existing:
            log.warn(f"Component already exists: {component.name}")
            return

        component.root_dir = self.root_dir / component.name
        self.merge_global_into_component(component)
        self.components.append(component)

    def ensure_included(self, name: str) -> FluxComponentConfig:
        component = next(filter(lambda x: x.name == name, self.components), None)
        if not component:
            component = FluxComponentConfig(name)
            self.add_component(component)

        return component

    def get_component(self, name: str) -> FluxComponentConfig:
        return next(filter(lambda x: x.name == name, self.components), None)

    def merge_global_into_component(self, component: FluxComponentConfig):
        global_config = self.file_manager.get_all_objects()
        component.file_manager.merge_config(global_config)

    def ensure_removed(self, name: str):
        self.components = [c for c in self.components if c.get("name") != name]

    def update_common_objects(self, files: list[FileSystemEntry]):
        self.file_manager.add_objects(files)

    def update_paths(self, root_app_dir: Path):
        for component in self.components:
            component.update_paths(root_app_dir / "components" / component.name)
        self.file_manager.update_paths(root_app_dir / "common_files")

    def validate_local_objects(self):
        for component in self.components:
            component.validate_local_objects()
        self.file_manager.validate_local_objects()

    def build_catalogue(self):
        # * = optional
        # get all files / dirs from chroot
        for component in self.components:
            component.build_catalogue()
        # files in chroot are not allowed. Must start with folder, then files / folders etc
        # maybe also disable some tld folders like /dev.
        # group them by common ancestor
        # Add each common ancestor as a managed_object (files and dirs)
        # confirm files in vault exist (or not) validate local file
        # get size of all files *
        # get size of all dirs (calculate from files) *
        ...
