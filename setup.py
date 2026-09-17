import os
from unittest.mock import patch
from setuptools import setup
from setuptools.command.sdist import sdist as _sdist

SOURCE_DATE_EPOCH = int(os.environ.get('SOURCE_DATE_EPOCH', '0'))

class reproducible_sdist(_sdist):
    """Set deterministic timestamps for all files and directories in the
    release tree and the gzip header before the archive is created.
    """
    def make_archive(self, base_name, format, root_dir=None, base_dir=None, owner=None, group=None):
        epoch = SOURCE_DATE_EPOCH

        if epoch:
            # Normalize the fully constructed release tree
            for root, dirs, files in os.walk(base_dir):
                for name in dirs:
                    os.utime(os.path.join(root, name), (epoch, epoch))
                for name in files:
                    os.utime(os.path.join(root, name), (epoch, epoch))
            # Also set the base directory itself
            os.utime(base_dir, (epoch, epoch))

            # Narrowly control gzip MTIME during archive creation
            with patch("time.time", return_value=epoch):
                return super().make_archive(
                    base_name,
                    format,
                    root_dir=root_dir,
                    base_dir=base_dir,
                    owner=owner,
                    group=group,
                )
        else:
            return super().make_archive(
                base_name,
                format,
                root_dir=root_dir,
                base_dir=base_dir,
                owner=owner,
                group=group,
            )

setup(
    cmdclass={"sdist": reproducible_sdist},
)
