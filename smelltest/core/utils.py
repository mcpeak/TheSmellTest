import os

def discover_files(path):
    try:
        for entry in os.scandir(path):
            if entry.is_dir(follow_symlinks=False):
                yield from discover_files(entry.path)
            else:
                yield entry
    except OSError as error:
        yield None
