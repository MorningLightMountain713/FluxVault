# so you don't need to quote foward lookahead typing
from __future__ import annotations

from pathlib import Path
from enum import Enum
from typing import BinaryIO
from dataclasses import dataclass, field
from jinja2 import Environment, BaseLoader
import aiofiles
from fluxvault.log import log

BUFFERSIZE = 1048576 * 50


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


class FileTooLargeError(Exception):
    """"""

    ...


tree_symbols = {
    "root_path": lambda size, path: f"{bytes_to_human(size)} {bcolors.OKBLUE}{path}{bcolors.ENDC}",
    "dir_terminal": lambda prefix, size, path: f"{prefix}└── {bytes_to_human(size)} {bcolors.OKBLUE}{path.name}{bcolors.ENDC}",
    "dir_not_terminal": lambda prefix, size, path: f"{prefix}├── {bytes_to_human(size)} {bcolors.OKBLUE}{path.name}{bcolors.ENDC}",
    "file_terminal_dir_not_last_file": lambda prefix, size, path: f"{prefix}{'    '}├── {bytes_to_human(size)} {path.name}",
    "file_terminal_dir_last_file": lambda prefix, size, path: f"{prefix}{'    '}└── {bytes_to_human(size)} {path.name}",
    "file_not_terminal_dir_not_last_file": lambda prefix, size, path: f"{prefix}{'│   '}├── {bytes_to_human(size)} {path.name}",
    "file_not_terminal_dir_last_file": lambda prefix, size, path: f"{prefix}{'│   '}└── {bytes_to_human(size)} {path.name}",
    "root_path_last_file": lambda prefix, size, path: f"{prefix}└── {bytes_to_human(size)} {path.name}",
    "root_path_not_last_file": lambda prefix, size, path: f"{prefix}├── {bytes_to_human(size)} {path.name}",
}


@dataclass
class ConcreteFsEntry:
    path: Path
    parent: ConcreteFsEntry | None = None
    children: list[ConcreteFsEntry] = field(default_factory=list)
    depth: int = 0
    last_modified: int = 0
    fs_type: FsType = FsType.UNKNOWN
    size: int = 0
    fh: BinaryIO | None = None

    def __str__(self):
        """This only gets called by directories. Doesn't it?"""
        # object_symbols = {"not_last": "├──", "last": "└──"}
        ancestor_symbols = {
            True: "    ",
            False: "│   ",
        }
        files = [x for x in self.children if x.fs_type == FsType.FILE]
        dirs = [x for x in self.children if x.fs_type == FsType.DIRECTORY]
        last_sibling_dir = False

        ancestors = self.parents()

        slots = []
        for index, ancestor in enumerate(ancestors):
            if index == len(ancestors) - 1:
                target = self
            else:
                target = ancestors[index + 1]
            last_sibling_dir = ancestor.last_sibling_dir(target)
            slots.append(last_sibling_dir)

        terminal_dir = slots.pop() if slots else False
        prefix = "".join([ancestor_symbols[x] for x in slots])

        template_str = """
            {%- if depth == 0 -%}
                {{tree_symbols['root_path'](size, path)}}
            {% elif terminal_dir -%}
                {{tree_symbols['dir_terminal'](prefix, size, path)}}
            {% else -%}
                {{tree_symbols['dir_not_terminal'](prefix, size, path)}}
             {% endif -%}
            {% for file in files -%}
                {% if depth == 0 -%}
                    {% if loop.index == files|length -%}
                        {% if dirs -%}
                            {{tree_symbols['root_path_not_last_file'](prefix, file.size, file.path)}}
                        {% else -%}
                            {{tree_symbols['root_path_last_file'](prefix, file.size, file.path)}}
                        {% endif -%}
                    {% else -%}
                        {{tree_symbols['root_path_not_last_file'](prefix, file.size, file.path)}}
                    {% endif -%}
                {% elif terminal_dir -%}
                    {% if loop.index == files|length -%}
                        {% if dirs -%}
                            {{tree_symbols['file_terminal_dir_not_last_file'](prefix, file.size, file.path)}}
                        {% else -%}
                            {{tree_symbols['file_terminal_dir_last_file'](prefix, file.size,file.path)}}
                        {% endif -%}
                    {% else -%}
                        {{tree_symbols['file_terminal_dir_not_last_file'](prefix, file.size, file.path)}}
                    {% endif -%}
                {% else -%}
                    {% if loop.index == files|length -%}
                        {% if dirs -%}
                            {{tree_symbols['file_not_terminal_dir_not_last_file'](prefix, file.size, file.path)}}
                        {% else -%}
                            {{tree_symbols['file_not_terminal_dir_last_file'](prefix, file.size, file.path)}}
                        {% endif -%}
                    {% else -%}
                        {{tree_symbols['file_not_terminal_dir_not_last_file'](prefix, file.size, file.path)}}
                    {% endif -%}
                {% endif -%}
            {% endfor -%}
            {% for dir in dirs -%}
                {{dir}}
            {%- endfor -%}"""

        env = Environment(loader=BaseLoader(), lstrip_blocks=True)
        # env.filters["bytes_to_human"] = bytes_to_human
        fs_template = env.from_string(template_str)

        return fs_template.render(
            path=self.path,
            depth=self.depth,
            files=files,
            dirs=dirs,
            size=self.size,
            terminal_dir=terminal_dir,
            prefix=prefix,
            tree_symbols=tree_symbols,
        )

    @classmethod
    def build_tree(cls, base_path: Path, depth: int = 0) -> ConcreteFsEntry:
        if not base_path.is_dir():
            raise ValueError("Base path must be a directory that exists")

        children: list[ConcreteFsEntry] = []

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

        for child in children:
            child.parent = parent

        return parent

    @property
    def sibling_dirs(self) -> list:
        # this is wrong. use parent (it works but we should use our own interface)
        return self.path.is_dir() and any(
            [x for x in self.path.parent.iterdir() if x.is_dir() and x != self.path]
        )

    @property
    def child_dirs(self) -> bool:
        return bool(len([x for x in self.children if x.path.is_dir()]))

    @property
    def readable(self) -> bool:
        """If this object can be called by read()"""
        return self.path.is_file()

    @property
    def storable(self) -> bool:
        """If this object can be used to store files"""
        return self.path.is_dir()

    def parents(self) -> list[ConcreteFsEntry]:
        """Get all ancestors up the file tree, finishing at root"""
        parents = []
        ancestor_count = self.depth
        while ancestor_count > 0:
            ancestor_count -= 1
            if not parents:
                parents.append(self.parent)
            else:
                parents.insert(0, parents[0].parent)
        return parents

    def last_sibling_dir(self, child: ConcreteFsEntry) -> bool:
        """Called from a child to a parent; Finds out if child is the last
        directory in parent's list of children"""
        if len(self.children):
            last = [x for x in self.children if x.fs_type == FsType.DIRECTORY][-1]
            return last.path == child.path
        return False

    # def last_sibling(self, child: ConcreteFsEntry) -> bool:
    #     if len(self.children):
    #         last = self.children[-1]
    #         return last.path == child.path
    #     return False

    def realize(self):
        """Will populate FsEntry with live file details"""
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

    async def _reader(self, chunk_size: int) -> bytes:
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

blimp = ConcreteFsEntry.build_tree(
    Path("/Users/davew/.vault/gravyboat/components/fluxagent/fake_root/racing")
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
