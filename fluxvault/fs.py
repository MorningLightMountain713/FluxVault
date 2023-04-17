# so you don't need to quote foward lookahead typing
from __future__ import annotations

import binascii
from collections.abc import Callable

# from typing import TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Generator
import time
import asyncio

import aiofiles

from fluxvault.helpers import RemoteStateDirective
from fluxvault.log import log

# if TYPE_CHECKING:
#     from fluxvault.fluxapp import RemoteStateDirective

BUFFERSIZE = 1048576 * 50

### BUILD NOTES ###

# File or dir
# └── = last file no more dirs
# ├── = last dir no files

# Depth
# "│   "
# "│   │   "
# "│   │   "
# "│   │   │   "

# if last dir at depth:
# └── = dir
# direct children files have "    " instead of "|   " for parent

# any child depths (greater than current depth) have
# "    " instead of "│   " at left

# "    " = spacer
# "|   " = ancestor line

# is parent last sibling? Yes Then spacer at parent depth -1

# slots. Each height has depth -1 slots

# slots are either spacers or ancestors

# eg

# spacer ancestor
# spacer ancestor ancestor spacer

### /BUILD NOTES ###


class FileTooLargeError(Exception):
    """"""

    ...


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def bytes_to_human(num, suffix="B"):
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


class FsType(Enum):
    DIRECTORY = 1
    FILE = 2
    UNKNOWN = 3


FORMATS: dict[str, Callable] = {
    "root_path": lambda size, path: f"{bytes_to_human(size)} {bcolors.OKBLUE}{path}{bcolors.ENDC}",
    "root_path_last_file": lambda prefix, size, path: f"{prefix}└── {bytes_to_human(size)} {path.name}",
    "root_path_not_last_file": lambda prefix, size, path: f"{prefix}├── {bytes_to_human(size)} {path.name}",
    "dir_terminal": lambda prefix, size, path: f"{prefix}└── {bytes_to_human(size)} {bcolors.OKBLUE}{path.name}{bcolors.ENDC}",
    "dir_not_terminal": lambda prefix, size, path: f"{prefix}├── {bytes_to_human(size)} {bcolors.OKBLUE}{path.name}{bcolors.ENDC}",
    "file_terminal_dir_last_file": lambda prefix, size, path: f"{prefix}{'    '}└── {bytes_to_human(size)} {path.name}",
    "file_terminal_dir_not_last_file": lambda prefix, size, path: f"{prefix}{'    '}├── {bytes_to_human(size)} {path.name}",
    "file_not_terminal_dir_last_file": lambda prefix, size, path: f"{prefix}{'│   '}└── {bytes_to_human(size)} {path.name}",
    "file_not_terminal_dir_not_last_file": lambda prefix, size, path: f"{prefix}{'│   '}├── {bytes_to_human(size)} {path.name}",
}


@dataclass
class CrcCacheItem:
    crc: int
    last_update: float = field(default_factory=time.monotonic)


@dataclass
class CrcCache:
    cache_items: dict[str, CrcCacheItem] = field(default_factory=dict)

    def get(self, name) -> int | None:
        if cache_item := self.cache_items.get(name):
            return cache_item.crc

    async def add(self, name, crc):
        self.cache_items[name] = CrcCacheItem(crc)
        # should be storing this somewhere
        asyncio.create_task(self.wait_and_remove(40, name))

    async def wait_and_remove(self, timeout, name):
        await asyncio.sleep(timeout)
        self.remove(name)

    def remove(self, name):
        try:
            del self.cache_items[name]
        except ValueError:
            pass


@dataclass
class ConcreteFsEntry:
    path: Path
    parent: ConcreteFsEntry | None = None
    children: list[ConcreteFsEntry] = field(default_factory=list)
    children_index: dict[str, int] = field(default_factory=dict)
    depth: int = 0
    last_modified: int = 0
    fs_type: FsType = FsType.UNKNOWN
    size: int = 0
    fh: BinaryIO | None = None
    crc_cache: CrcCache = field(default_factory=CrcCache)

    def __str__(self):
        """"""
        ancestor_symbols = {
            True: "    ",
            False: "│   ",
        }

        # object_symbols = {"not_last": "├── ", "last": "└── "}
        # file_symbols = {"not_last_dir": "│   ", "last_dir": "    "}

        files = [x for x in self.children if x.fs_type == FsType.FILE]
        dirs = [x for x in self.children if x.fs_type == FsType.DIRECTORY]
        is_last_sibling_dir = False

        ancestors = self.parents()

        slots = []
        for index, ancestor in enumerate(ancestors):
            if index == len(ancestors) - 1:
                target = self
            else:
                target = ancestors[index + 1]
            is_last_sibling_dir = ancestor.last_sibling_dir(target)
            slots.append(is_last_sibling_dir)

        terminal_dir = slots.pop() if slots else False
        prefix = "".join([ancestor_symbols[x] for x in slots])

        if self.depth == 0:
            dir_type = "root_path"
            params = [self.size, self.path]
        elif terminal_dir:
            dir_type = "dir_terminal"
            params = [prefix, self.size, self.path]
        else:
            dir_type = "dir_not_terminal"
            params = [prefix, self.size, self.path]

        directory = self.formatter(dir_type)(*params)

        formatted_files = []
        for index, file in enumerate(files):
            params = [prefix, file.size, file.path]
            if self.depth == 0:
                file_type = "root_path_not_last_file"
                if index + 1 == len(files) and not dirs:
                    file_type = "root_path_last_file"
            elif terminal_dir:
                file_type = "file_terminal_dir_not_last_file"
                if index + 1 == len(files) and not dirs:
                    file_type = "file_terminal_dir_last_file"
            else:
                file_type = "file_not_terminal_dir_not_last_file"
                if index + 1 == len(files) and not dirs:
                    file_type = "file_not_terminal_dir_last_file"
            formatted_files.append(self.formatter(file_type)(*params))

        # the str(d) list comp is recursive. I.e. - it calls this function
        return "\n".join([directory, *formatted_files, *[str(d) for d in dirs]])

    @classmethod
    def log_objects_in_dir(cls, dir: Path):
        if not dir.is_dir():
            return

        for child in dir.iterdir():
            log.info(f"Existing fake root object: {child} (before linking)")

    @classmethod
    def contains(cls, name: Path, dir: Path) -> bool:
        """If the directory contains the file name"""
        return (dir / name).exists()

    @classmethod
    def are_files_in_dir(cls, dir: Path) -> bool:
        if not dir.is_dir():
            return False

        return any(x.is_file() for x in dir.iterdir())

    @classmethod
    def entries_in_dir(cls, dir: Path) -> Generator[Path, None, None]:
        if not dir.is_dir:
            return []

        yield from dir.iterdir()

    @classmethod
    def find_first_path(cls, target: Path, locations: list[Path]) -> Path | None:
        """Pass in a path, it will return it if it exists, and if not,
        it will search in in paths (dirs) to find a name match. It found
        returns the full path"""

        first_match_dir = next(
            filter(lambda x: ConcreteFsEntry.contains(target, x), locations)
        )

        return first_match_dir

    @classmethod
    def build_tree(cls, base_path: Path, depth: int = 0) -> ConcreteFsEntry:
        children: list[ConcreteFsEntry] = []
        children_index = {}

        if not base_path.exists():
            return ConcreteFsEntry(base_path)

        if base_path.is_dir():
            for child in sorted(base_path.iterdir()):
                if child.is_dir():
                    fs_entry = ConcreteFsEntry.build_tree(child, depth + 1)
                elif child.is_file():
                    fs_entry = ConcreteFsEntry(
                        child, None, [], depth + 1, fs_type=FsType.FILE
                    )
                else:
                    raise Exception("FUCKED")

                children.append(fs_entry)

        parent = ConcreteFsEntry(
            base_path,
            parent=None,
            children=children,
            depth=depth,
            fs_type=FsType.DIRECTORY,
        )

        for index, child in enumerate(children):
            key = child.path.relative_to(parent.path)
            children_index[key] = index
            child.parent = parent

        parent.children_index.update(children_index)

        return parent

    @property
    def exists(self) -> bool:
        return self.path.exists()

    @property
    def empty(self) -> bool:
        """Are we empty"""
        return self.get_size == 0

    @property
    def child_dirs(self) -> bool:
        """Lets the caller know if this object has any children dirs"""
        return bool(len([x for x in self.children if x.path.is_dir()]))

    @property
    def readable(self) -> bool:
        """If this object can be called by read()"""
        return self.path.is_file()

    @property
    def storable(self) -> bool:
        """If this object can be used to store files"""
        return self.path.is_dir()

    @property
    def sibling_dirs(self) -> list:
        # this is wrong. use parent (it works but we should use our own interface)
        return self.path.is_dir() and any(
            [x for x in self.path.parent.iterdir() if x.is_dir() and x != self.path]
        )

    @staticmethod
    def formatter(section) -> Callable:
        return FORMATS[section]

    def get_child(self, target: Path) -> ConcreteFsEntry | None:
        relative_path = target.relative_to(self.path)

        if len(relative_path.parts) > 1:
            child_index = self.children_index.get(Path(relative_path.parts[0]))
            return self.children[child_index].get_child(target)

        if child_index := self.children_index.get(relative_path, None):
            return self.children[child_index]

    def get_partial_size(self, fragments: list[Path]) -> int:
        """Only makes sense to be called from a directory. However gets called
        recursively so will be for a file too"""

        sizes = []
        for target_path in fragments:
            if target_path == self.path:
                continue

            if target := self.get_child(target_path):
                sizes.append(target.size)
                continue

        return sum(sizes)

    def get_size(self) -> int:
        match self.fs_type:
            case FsType.FILE:
                return self.path.stat().st_size
            case FsType.DIRECTORY:
                return sum(
                    f.stat().st_size for f in self.path.glob("**/*") if f.is_file()
                )

    def root(self) -> ConcreteFsEntry:
        if self.depth == 0:
            return self

        ancestor_count = self.depth
        parent = None

        while ancestor_count > 0:
            ancestor_count -= 1
            if not parent:
                parent = self.parent
            else:
                parent = parent.parent

        return parent

    def parents(self) -> list[ConcreteFsEntry]:
        """Get all ancestors up the file tree, finishing at root"""
        parents: list[ConcreteFsEntry] = []
        ancestor_count = self.depth

        while ancestor_count > 0:
            ancestor_count -= 1
            if not parents:
                parents.append(self.parent)
            else:
                parents.insert(0, parents[0].parent)
        return parents

    def decendants(self) -> list[Path]:
        """Returns all child paths down the tree"""
        if self.path.is_dir():
            return [f for f in self.path.glob("**/*")]
        else:
            return []

    def last_sibling_dir(self, child: ConcreteFsEntry) -> bool:
        """Called from a child to a parent; Finds out if child is the last
        directory in parent's list of children"""
        if len(self.children):
            last = [x for x in self.children if x.fs_type == FsType.DIRECTORY][-1]
            return last.path == child.path
        return False

    def last_sibling(self, child: ConcreteFsEntry) -> bool:
        if len(self.children):
            last = self.children[-1]
            return last.path == child.path
        return False

    def recurse(self) -> Generator[ConcreteFsEntry, None, None]:
        yield self

        for child in self.children:
            yield from child.recurse()

    def realize(self):
        """Will populate FsEntry (and children) with live file details"""
        for child in self.children:
            child.realize()

        if self.readable:
            self.fs_type = FsType.FILE
            stat = self.path.stat()
            self.size = stat.st_size
            self.last_modified = stat.st_mtime

        elif self.storable:
            self.fs_type = FsType.DIRECTORY

            files_size = sum(f.size for f in self.children if f.readable)
            dirs_size = sum(d.size for d in self.children if d.storable)

            self.size = files_size + dirs_size
            self.last_modified = self.path.stat().st_mtime

    async def _reader(self, chunk_size: int) -> Generator[bytes, None, None]:
        if not self.fh:
            self.fh = await aiofiles.open(self.path, "rb").__aenter__()
        yield await self.fh.read(chunk_size)

    async def read(self, chunk_size: int | None = None) -> bytes:
        f"""Reads underlying file if entry is under {bytes_to_human(BUFFERSIZE)}, or
        reads up to chunk_size bytes. Uses a generator so file bytes aren't stored in buffer."""
        if chunk_size == None:  # reading until eof
            if self.size > BUFFERSIZE:
                raise FileTooLargeError(str(self.path))
        if not self.readable:
            raise FileNotFoundError(str(self.path))

        return await anext(self._reader(chunk_size))

    async def close(self):
        await self.fh.close()
        self.fh = None

    ### CRC OPERATIONS

    def crc_file(self, filename: Path, crc: int) -> int:
        if cache_crc := self.crc_cache.get(str(filename)):
            return cache_crc

        crc = binascii.crc32(filename.name.encode(), crc)

        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 128), b""):
                crc = binascii.crc32(chunk, crc)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.crc_cache.add(str(filename), crc))

        return crc

    def crc_directory(self, directory: Path, crc: int, name: str = "") -> int:
        if cache_crc := self.crc_cache.get(str(directory)):
            return cache_crc

        dir_name = name if name else directory.name
        crc = binascii.crc32(dir_name.encode(), crc)

        for path in sorted(directory.iterdir(), key=lambda p: str(p).lower()):
            crc = binascii.crc32(path.name.encode(), crc)

            if path.is_file():
                crc = self.crc_file(path, crc)
            elif path.is_dir():
                crc = self.crc_directory(path, crc)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.crc_cache.add(str(directory), crc))

        return crc

    def crc32(self, name: str = "") -> int:
        if self.fs_type == FsType.DIRECTORY:
            return self.crc_directory(self.path, 0, name=name)
        elif self.fs_type == FsType.FILE:
            return self.crc_file(self.path, 0)

    def get_file_hash(self, file: Path):
        crc = self.crc_file(file, 0)
        return {str(file): crc}

    def get_directory_hashes(
        self, dir: Path | None = None, name: str | None = None
    ) -> dict[str, int]:
        """Returns a dictionary of every fs object and it's corresponding crc32"""
        hashes = {}

        # fix all this... needs to hash the filename too, otherwise
        # we get the wrong hash if new empty file added
        if not dir and not self.storable:
            return hashes

        p = dir if dir else self.path

        dir_name = name if name else p.name

        crc = binascii.crc32(dir_name.encode())
        hashes.update({str(p): crc})

        for path in sorted(p.iterdir(), key=lambda p: str(p).lower()):
            if path.is_dir():
                hashes.update(self.get_directory_hashes(path))

            elif path.is_file():
                hashes.update(self.get_file_hash(path))

        return hashes


@dataclass
class FsEntryStateManager:
    """Wrapper around ConcreteFsEntry. An abstract Filesystem. Syncs state from local to remote
    objects. From Keeper point of view, the StreamWriter for the remote system
    is the filesystem"""

    name: Path  # dir or file
    remit: RemoteStateDirective
    local_parent: Path | None = None
    remote_workdir: Path = Path("/tmp")
    local_crc: int = 0
    remote_crc: int = 0
    validated_remote_crc: int = 0
    keeper_context: bool = True  # Eventually share these objects
    remote_object_exists: bool = False
    in_sync: bool = False
    concrete_fs: ConcreteFsEntry | None = None
    # root_name: str = ""

    @property
    def local_path(self):
        return self.local_parent / self.name

    @property
    def empty(self):
        return self.concrete_fs.empty

    @property
    def local_object_exists(self):
        return self.concrete_fs.exists

    @property
    def storable(self):
        return self.concrete_fs.storable

    @property
    def readable(self):
        return self.concrete_fs.readable

    @property
    def absolute_remote_path(self) -> Path:
        # this is ugly, fix
        # if self.concrete_fs.parent:
        #     print("CONCRETE FS PARENT", self.concrete_fs.parent.path)
        # else:
        #     print("NO CONCRETE FS PARENT")
        # print("NAME", self.name)
        # # this is the fileserver root
        # if self.concrete_fs.parent == None:

        #     return self.remote_workdir

        # fileserver
        # if self.root_name:
        #     return self.remote_workdir / self.root_name

        if self.concrete_fs.parent and self.concrete_fs.parent.path.name == "fake_root":
            return "/" / Path(self.name)

        match self.remit.remote_dir:
            case x if x and x.is_absolute():
                return x / self.name
            case x if x:
                return self.remote_workdir / self.remit.remote_dir / self.name
            case x if not x:
                return self.remote_workdir / self.name

    @property
    def absolute_remote_dir(self) -> Path:
        match self.remit.remote_dir:
            case x if x and x.is_absolute():
                return x
            case x if x:
                return self.remote_workdir / self.remit.remote_dir
            case x if not x:
                return self.remote_workdir

    def root(self) -> Path:
        return self.concrete_fs.root().path

    # just use property
    def set_syncronized(self):
        self.in_sync = True

    # BUILD THIS
    def serialize(self):
        ...

    def validate_local_object(self):
        # this doesn't make sense anymore, validation is done as part of instantiation
        # If we're the root object, fake the name for crc
        # if self.concrete_fs.depth == 0:
        #     self.local_crc = self.concrete_fs.crc32(name=self.name)
        # else:
        self.local_crc = self.concrete_fs.crc32()

    def compare_objects(self):
        """"""
        if not self.local_object_exists:
            return

        if not self.remote_crc:  # remote file crc is 0 if it doesn't exist
            self.remote_object_exists = False
            self.in_sync = False

            if self.local_crc:
                log.info(f"Agent needs new object {self.name}... sending")
                return

        self.remote_object_exists = True

        if self.remote_crc != self.local_crc:
            self.in_sync = False
            if (
                self.validated_remote_crc == self.remote_crc
                and self.local_object_exists
            ):
                log.info(
                    f"Agent remote object {self.name} is different than local object but has been validated due to sync strategy"
                )
                return

            if self.local_object_exists:
                log.info(
                    f"Remote object {self.name} CRC: {self.remote_crc} Local object CRC: {self.local_crc}... validating difference"
                )
                return

        if self.remote_crc == self.local_crc:
            # generates too many log messages
            # log.info(f"Agent object {self.name} is up to date... skipping!")
            self.in_sync = True


@dataclass
class FsStateManager:
    """File System State Manager"""

    managed_objects: list[FsEntryStateManager] = field(default_factory=list)
    directives: list[RemoteStateDirective] = field(default_factory=list)
    # local_workdir: Path | None = None
    # remote_workdir: Path | None = None

    def __iter__(self):
        yield from self.managed_objects

    @classmethod
    def filter_hierarchy(
        cls, current_path: Path, existing_paths: list[Path]
    ) -> list[Path]:
        # this needs heavy testing

        paths = existing_paths
        for existing_path in existing_paths:
            if current_path.is_relative_to(existing_path):
                # our ancestor is already in the list. We will get replaced
                # when they get synced (don't add ourselves)
                return paths

            elif existing_path.is_relative_to(current_path):
                # we are higher up the tree.. remove existing_path and
                # install ourselves
                paths.remove(existing_path)
                paths.append(current_path)
                return paths

        # sibling
        paths.append(current_path)

        return paths

    def set_syncronized(self, targets: list[Path]):
        for target in targets:
            if entry := self.get_object_by_local_path(target):
                entry.set_syncronized()

    def get_directive_by_path(self, path: Path) -> RemoteStateDirective | None:
        return next(
            filter(
                lambda x: x.content_source == path.parent and x.name == path.name,
                self.directives,
            ),
            None,
        )

    def get_directive_by_remote_path(self, path: Path) -> RemoteStateDirective:
        return next(
            filter(
                lambda x: x.remote_dir == path.parent and x.name == path.name,
                self.directives,
            ),
            None,
        )

    def add_directives(self, directives: list[RemoteStateDirective]):
        for directive in directives:
            self.add_directive(directive)

    def add_directive(self, directive: RemoteStateDirective):
        if isinstance(directive, RemoteStateDirective):
            self.directives.append(directive)
        else:
            log.warn(
                f"Directive: {directive} is not of type `RemoteStateDirective`. Skipping..."
            )

    def add_objects(self, objects: list):
        for obj in objects:
            self.add_object(obj)

    def add_object(self, fs_object: FsEntryStateManager):
        if isinstance(fs_object, FsEntryStateManager):
            self.managed_objects.append(fs_object)
        else:
            log.warn(
                f"FsObject: {fs_object} is not of type `FsEntryStateManager`. Skipping..."
            )

    def absolute_remote_dirs(self) -> list[Path]:
        return [x.absolute_remote_path for x in self.managed_objects if x.storable]

    def absolute_remote_paths(self) -> list[str]:
        return [str(x.absolute_remote_path) for x in self.managed_objects]

    # def merge_config(self, objects):
    #     for obj in objects:
    #         if isinstance(obj, RemoteStateDirective):
    #             self.managed_objects.append(obj)
    #         else:
    #             log.error(
    #                 f"Object of type {type(obj)} added to managed_objects, must be `RemoteStateDirective`"
    #             )

    def get_object_by_remote_path(self, remote: Path) -> FsEntryStateManager:
        # just lambda
        for fs_object in self.managed_objects:
            path = fs_object.absolute_remote_path

            if path == remote:
                return fs_object

    def get_object_by_local_path(self, local: Path) -> FsEntryStateManager:
        # just lambda
        for fs_object in self.managed_objects:
            path = fs_object.concrete_fs.path

            if path == local:
                return fs_object

    def get_all_objects(self) -> list[FsEntryStateManager]:
        return self.managed_objects

    def update_paths(self, local: Path, remote: Path | None = None):
        self.working_dir = local
        self.remote_workdir = remote

    def validate_local_objects(self):
        for obj in self.managed_objects:
            obj.validate_local_object()


# example (needs updated for parent, fh, last_modified, depth)

# blah = ConcreteFsEntry(
#     Path("/tmp/rangi"),
#     fs_type=FsType.DIRECTORY,
#     size=0,
#     children=[
#         ConcreteFsEntry(
#             Path("/tmp/rangi/bluht.txt"),
#             depth=1,
#             fs_type=FsType.FILE,
#             size=0,
#         ),
#         ConcreteFsEntry(
#             Path("/tmp/rangi/weiner"),
#             depth=1,
#             fs_type=FsType.FILE,
#             size=0,
#         ),
#         ConcreteFsEntry(
#             Path("/tmp/rangi/wrongo"),
#             depth=1,
#             fs_type=FsType.DIRECTORY,
#             size=0,
#             children=[
#                 ConcreteFsEntry(
#                     Path("/tmp/rangi/wrongo.job.exe"),
#                     depth=2,
#                     fs_type=FsType.FILE,
#                     size=0,
#                 )
#             ],
#         ),
#     ],
# )

if __name__ == "__main__":
    blimp = ConcreteFsEntry.build_tree(
        # Path("/Users/davew/.vault/gravyboat/components/fluxagent/fake_root/racing")
        # Path("/Users/davew/.vault")
        Path("/Users/davew/code/flux/fluxvault/LICENSE")
    )
    blimp.realize()
    print(blimp)

    # async def main():
    #     chug = ConcreteFsEntry(
    #         Path("/tmp/rangi/ubu/ubuntu-22.04.1-live-server-amd64.iso"),
    #         depth=0,
    #         fs_type=FsType.UNKNOWN,
    #         size=0,
    #     )
    #     print(await chug.read())
    #     print(await chug.read(5000))
    #     await chug.close()

    # asyncio.run(main())
