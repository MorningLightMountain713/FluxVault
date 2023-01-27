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
    local_path: Path
    remote_path: Path
    local_workdir: Path = field(default_factory=Path)
    local_crc: int = 0
    remote_crc: int = 0
    keeper_context: bool = True
    remote_object_exists: bool = False
    local_object_exists: bool = False
    in_sync: bool = False
    validated_remote_crc: int = 0
    file_data: bytes = b""
    sync_strategy: SyncStrategy = SyncStrategy.STRICT

    def is_dir(self) -> bool:
        return (self.local_workdir / self.local_path).is_dir()

    def expanded_remote_path(self) -> str:
        return (
            str(self.remote_path / self.local_path)
            if self.local_path != self.remote_path
            else str(self.local_path)
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
        # print("local absolulte path", str(p))

        if not p.exists():
            p_common = self.local_workdir.parent / "common" / p.name

            if (p_common).exists():

                self.local_workdir = self.local_workdir.parent / "common"
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
            self.local_crc = self.crc_file(p, 0)
        elif p.is_dir():
            self.local_crc = self.crc_directory(p, 0)

    def compare_objects(self) -> dict:
        if not self.local_object_exists:
            return

        path = self.local_path
        if self.local_path != self.remote_path:
            path = self.remote_path / self.local_path
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
    root_dir: Path = field(default_factory=Path)
    flattened: bool = False

    def __iter__(self):
        yield from self.managed_objects

    @classmethod
    def filter_hierarchy(
        cls, current_path: Path, existing_paths: list[Path]
    ) -> list[Path]:
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

    def expanded_remote_paths(self) -> list[str]:
        return [
            str(x.remote_path / x.local_path)
            if x.local_path != x.remote_path
            else str(x.local_path)
            for x in self.managed_objects
        ]

    def merge_config(self, objects):
        for obj in objects:
            if isinstance(obj, FileSystemEntry):
                self.managed_objects.append(obj)
            else:
                log.error(
                    f"Object of type {type(obj)} added to file manager, must be `FileSystemEntry`"
                )

    def add_objects(self, objects: list):
        for obj in objects:
            self.add_object(obj)

    def add_object(self, obj: FileSystemEntry):
        obj.local_workdir = self.root_dir
        self.managed_objects.append(obj)

    def get_object_by_remote_path(self, remote: Path) -> FileSystemEntry:
        for obj in self.managed_objects:
            path = (
                obj.remote_path / obj.local_path
                if obj.local_path != obj.remote_path
                else obj.local_path
            )

            if path == remote:
                return obj

    def get_all_objects(self) -> list[FileSystemEntry]:
        return self.managed_objects

    # ToDo: Rename
    def objects_to_agent_list(self) -> list:
        # ToDo: Composition
        objects = []
        for obj in self.managed_objects:
            if obj.local_object_exists and (
                not obj.remote_object_exists or not obj.in_sync
            ):
                if (
                    obj.remote_object_exists
                    and obj.sync_strategy == SyncStrategy.ENSURE_CREATED
                ):
                    continue

                path_str = (
                    str(obj.remote_path / obj.local_path)
                    if obj.local_path != obj.remote_path
                    else str(obj.local_path)
                )
                uncompressed = False
                is_dir = False

                abs_local_path = obj.local_workdir / obj.local_path
                if not obj.is_dir():
                    ONE_MB = 1048576 * 1

                    size = size_of_object(abs_local_path)
                    if size > ONE_MB:
                        log.info(
                            f"File {obj.local_path} with size {bytes_to_human(size)} is larger than uncompressed limit... compressing"
                        )
                        data = tar_object(abs_local_path)
                    else:  # < 1MB
                        uncompressed = True
                        with open(abs_local_path, "rb") as f:
                            data = f.read()

                if obj.is_dir():
                    is_dir = True
                    is_empty = not any((abs_local_path).iterdir())
                    if is_empty:
                        data = ""
                    else:  # we need to tar up son
                        fh = io.BytesIO()
                        # lol, hope the files aren't too big, or, you got plenty of ram
                        with tarfile.open(fileobj=fh, mode="w|bz2") as tar:
                            tar.add(
                                self.root_dir / obj.local_path,
                                # arcname=obj.local_path.name,
                                arcname="",
                            )
                        data = fh.getvalue()
                objects.append(
                    {
                        "path": path_str,
                        "data": data,
                        "is_dir": is_dir,
                        "uncompressed": uncompressed,
                    }
                )
        return objects

    def update_root_dir(self, dir: Path):
        self.root_dir = dir
        for obj in self.managed_objects:
            obj.local_workdir = self.root_dir
            obj.validate_local_object()


@dataclass
class FluxComponentConfig:
    name: str
    file_manager: FileSystemeGroup = field(default_factory=FileSystemeGroup)
    tasks: list[FluxTask] = field(default_factory=list)
    root_dir: Path = field(default_factory=Path)
    working_dir: Path = Path("/tmp")

    def update_root_dir(self, dir: Path):
        # change name to update dirs
        # root dir referes to where the physical files are
        # working dir is where the remote end puts them
        self.root_dir = dir
        self.file_manager.update_root_dir(self.root_dir)

    def add_tasks(self, tasks: list):
        for task in tasks:
            self.add_task(task)

    def add_task(self, task: FluxTask):
        self.tasks.append(task)

    def get_task(self, name) -> FluxTask:
        for task in self.tasks:
            if task.name == name:
                return task


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

    def update_root_dir(self, dir: Path):
        self.root_dir = dir
        for component in self.components:
            component.update_root_dir(self.root_dir / component.name)
        self.file_manager.update_root_dir(self.root_dir / "common")
