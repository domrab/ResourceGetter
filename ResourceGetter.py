# MIT License
#
# Copyright (c) 2023 domrab
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import os
import json
import warnings
import traceback

try:
    import pathlib
except ImportError:
    raise Exception("Could not load pathlib package. Please install pathlib to use this module!")

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False
    warnings.warn("Could not load 'yaml' package. Will not be able to parse *.yaml files by default!", Warning)


PY2 = PY3 = False
if sys.version_info.major == 2:
    PY2 = True
elif sys.version_info.major == 3:
    basestring = str
    PY3 = True


__author__ = "Dominik Haase"
__maintainer__ = "Dominik Haase"
__version__ = "1.0.0"

# severity level for incidents:
# MESSAGE: print to stdout
# WARNING: warnings.warn
# ERROR: raise Exception
MESSAGE = 0
WARNING = 1
ERROR = 2

# OVERRIDE_EXCEPTHOOK, if true, this overrides sys.excepthook to allow for a shortened, more convenient stracktrace
# this has to be set before the module is loaded eg in case you are overriding sys.excepthook yourself before
# if you do turn it off but still want to take advantage, you can integrate the RG_excepthook below in your method
OVERRIDE_EXCEPTHOOK = True


# SHOW_FULL_STACKTRACE only works when RG_excepthook is used. It limits the stacktrace
# when an RGError is raised to only show up until the point you call a ResourceGetter function
SHOW_FULL_STACKTRACE = False


# _TYPES contains the automatically registered the custom types like RGstr or RGfloat
# _PARSERS contains the manually registered file parsers like parse_json by default
_D_TYPES, _D_PARSERS = {}, {}


class RGError(Exception):
    """Custom Exception for this module used in Incidents"""


class RGWarning(Warning):
    """Custom Warning for this module used in Incidents"""


class Incident(object):
    _I_SEVERITY = ERROR
    _S_NAME = None

    def __init__(self, s_name, i_severity):
        """Custom type to handle Exceptions/Warnings/Messages

        Args:
            s_name (str):
                the name for this

            i_severity (int):
                use MESSAGE (0), WARNING (1), OR ERROR (2)
        """
        self._S_NAME = s_name
        self.set_severity(i_severity)

    def __call__(self, s_message, *args):
        """This is used instead of print/sys.stdout.write, warnings.warn, and raise Exception

        Args:
            s_message (str):
                the message string

            *args:
                the arguments to format s_message with
        """
        s_message = s_message.format(*[str(arg) for arg in args])
        i_severity = self.get_i_severity()

        if i_severity == ERROR:
            raise RGError("{}: {}".format(self._S_NAME, s_message.replace("\n", "\n    ")))

        elif i_severity == WARNING:
            warnings.warn(s_message.replace("\n", "\n    "), RGWarning)
            return

        elif i_severity == MESSAGE:
            print("# {}: {}".format(self._S_NAME, s_message.replace("\n", "\n#   " + (" " * len(self._S_NAME)))))
            return

        raise Exception("Invalid severity level: {}".format(i_severity))

    def get_i_severity(self):
        """getter for severity of this incident"""
        return self._I_SEVERITY

    def set_severity(self, i_severity):
        """setter for severity of this incident

        Args:
            i_severity (int):
                severity for this incident, should be MESSAGE (0), WARNING (1), or ERROR (2)

        Raises:
            ValueError: if an invalid severity is given
        """
        if i_severity not in [ERROR, WARNING, MESSAGE]:
            raise ValueError("Invalid severity: {}".format(i_severity))

        self._I_SEVERITY = i_severity


class _RGObject(object):
    """
    base class adding an expand() function to custom RG classes
    """
    def expand(self, b_env_vars=True, b_user=True, **kwargs):
        """Expand a string or path containing common substition methods

        Args:
            b_env_vars (bool: True):
                expand env vars like '%WINDOWSSTYLE%' or '$LINUXSTYLE'

            b_user (bool: True):
                expand '~/Documents'

            **kwargs (dict):
                expand using python formatting '{kwarg1}/{kwarg2}'

        Returns:
            self (_RGObject): instance of same type with modified value

        """

        s_value = self
        if isinstance(s_value, pathlib.Path):
            s_value = str(s_value)

        elif not isinstance(s_value, basestring):
            return self

        if b_env_vars:
            s_value = os.path.expandvars(s_value)
        if b_user:
            s_value = os.path.expanduser(s_value)

        for key, value in kwargs.items():
            s_value = s_value.replace("{%s}" % key, value)

        return self.__class__(s_value)


class ResourceManager(object):
    """
    instances of this class are used for managing resources
    """
    _S_PREFIX = None
    _SOURCE = None
    _D_DATA = None
    _D_OVERRIDES = None
    _XAA_TRANSFORMERS = None

    def __init__(self, s_category, source, b_load=True):
        """resource manager constructor

        Args:
            s_category (str):
                name of the file this manager takes care of

            source (str|list[str]):
                str: env var pointing to the paths of the containing folders OR
                list: list of paths to search for

            b_load (bool: True):
                if true, auto loads the available files in __init__()

        Raises:
            NotImplementedError: if no file parser can be found for a certain extension

        Example:
            CONFIG = ResourceManager("config")
            CONFIG("PATHS.OUTPUT")  # same as `CONFIG.get("PATHS.OUTPUT")
            >> '/the/output/path'

            CONFIG.override("PATHS.OUTPUT", "/this/path/has/an/override")

            CONFIG("PATHS.OUTPUT")
            >> '/this/path/has/an/override'

            CONFIG.info("PATHS.OUTPUT")
            >> 'override'

            CONFIG.remove_override("PATHS.OUTPUT")
            CONFIG.info("PATHS.OUTPUT")
            >> /the/path/to/your/config.json
        """
        if "*" in s_category:
            INCIDENT_WILDCARD("Using '*' in category can cause problems\nwhen there are conflicts between files!")

        self._S_PREFIX = s_category
        self._SOURCE = source
        self._D_DATA = {}
        self._D_OVERRIDES = {}
        self._XAA_TRANSFORMERS = []

        if not b_load:
            return

        def d_flatten(data, s_path, s_prefix=''):
            """INTERNAL: flatten dictionary into `.` concatenated strings:
                {Foo: {Bar: test}} -> {Foo.Bar: test}

            Args:
                data:
                    data

                s_path (str):
                    current path

                s_prefix (str):
                    prefix (file name)

            Returns:

            """
            flattened = {}
            if isinstance(data, dict):
                for s_key, value in data.items():
                    s_new_key = s_prefix + s_key if s_prefix else s_key
                    if isinstance(value, dict):
                        flattened.update(d_flatten(value, s_path, s_new_key + '.'))
                    else:
                        flattened[s_new_key] = value, s_path
            elif isinstance(data, list):
                for i_index, item in enumerate(data):
                    flattened.update(d_flatten(item, s_path, s_prefix + str(i_index) + '.'))
            return flattened

        for path, s_extension in self._get_all_source_files()[::-1]:
            s_extension = str(path).rpartition(".")[2]

            x_parser = _D_PARSERS.get(s_extension.lower(), None)
            if x_parser is None:
                INCIDENT_NO_EXTENSION("No parser found for: '{}' ({})", s_extension, path)
                continue
                # raise NotImplementedError("Extension: '{extension}'".format(extension=s_extension))

            self._D_DATA.update(d_flatten(x_parser(path), str(path)))

    def __call__(self, s_resource, b_reload=False):
        """Shortcut for instance.get()

        Args:
            s_resource (str):
                name of the resource

            b_reload (bool: False):
                if this should be reloaded from the file even if it has been cached previously

        Returns:
            result (_RGObject)
        """
        return self.get(s_resource, b_reload=b_reload)

    def _get_source_paths(self):
        """get a list of paths either from the supplied list or the env var if a string is given

        Returns:
            paths (list[pathlib.Path]): paths to directories containing resource files
        """
        s_sep = ";" if os.name == "nt" else ":"
        sa_source_paths = self._SOURCE

        if isinstance(self._SOURCE, basestring):
            sa_source_paths = os.environ.get(self._SOURCE, "").split(s_sep)

        paths = [pathlib.Path(p) for p in sa_source_paths]

        # check if there are any files in there
        for path in paths:
            if not path.is_file():
                continue
            warnings.warn("Expected directory but found file: {path}".format(path=path), RGWarning)

        return paths

    def _get_source_files(self, path):
        return [p for p in path.resolve().glob(self._S_PREFIX + ".*") if p.is_file()]

    def _get_all_source_files(self):
        return [(f, str(f).rpartition(".")[2]) for p in self._get_source_paths() for f in self._get_source_files(p)]

    def _get_resource(self, s_resource, b_reload=False):
        """internal main function to handle resources and overrides

        Args:
            s_resource (str):
                name of the resource

            b_reload (bool: False):
                if this should be reloaded from the file even if it has been cached previously

        Returns:
            result: (_RGObject, str): resource + path

        Raises:
            RGError:
                - if wildcard `*` is found in s_resource
                - if resource could not be found

            NotImplementedError:
                - if file extension does not have a parser
        """
        if s_resource in self._D_OVERRIDES:
            return self._D_OVERRIDES[s_resource]

        if s_resource in self._D_DATA and not b_reload:
            return self._D_DATA[s_resource]

        if "*" in s_resource:
            raise RGError("No wildcard search allowed yet!")

        sa_parts = s_resource.split(".")
        for path, s_extension in self._get_all_source_files():
            x_parser = _D_PARSERS.get(s_extension.lower(), None)
            if x_parser is None:
                warnings.warn("No parser found for: '{extension}' ({path})".format(extension=s_extension, path=path), RGWarning)
                continue

            data = x_parser(path)
            while sa_parts and (sa_parts[0] in data.keys()):
                s_token = sa_parts.pop(0)
                data = data[s_token]

            if sa_parts:
                continue

            self._D_DATA[s_resource] = data, str(path)
            return self._D_DATA[s_resource]

        raise RGError("Could not find {resource}".format(resource=s_resource))

    def get(self, s_resource, b_reload=False):
        """get the resource

        Args:
            s_resource (str):
                name of the resource

            b_reload (bool: False):
                if this should be reloaded from the file even if it has been cached previously

        Returns:
            result (_RGObject)
        """
        value, _ = self._get_resource(s_resource, b_reload=b_reload)

        # apply transformers if applicable
        for x_check, x_transform in self._XAA_TRANSFORMERS[::-1]:
            if x_check(value):
                value = x_transform(value)
                break

        # subclass the _RGObject type
        typ = type(value)
        if typ not in _D_TYPES:
            _D_TYPES[typ] = type("RG{type}".format(type=type(value).__name__), (type(value), _RGObject), {})

        return _D_TYPES[typ](value)

    def info(self, s_resource):
        """get the location the resource is currently sourced from, if override, then `override`

        Args:
            s_resource (str):
                name of the resource

        Returns:
            result (str)
        """
        return self._get_resource(s_resource)[1]

    def override(self, s_resource, value):
        """set an override for s_resource

        Args:
            s_resource (str):
                name of the resource

            value (typing.Any):
                value
        """
        self._D_OVERRIDES[s_resource] = (value, "override")

    def remove_override(self, s_resource):
        """delete and existing override (passes if override does not exist)

        Args:
            s_resource (str):
                name of the resource
        """
        if s_resource in self._D_OVERRIDES:
            self._D_OVERRIDES.pop(s_resource)

    @staticmethod
    def register_parser(s_format, x_parser):
        """staticmethod to register a parser to the ResourceGetter module

        Args:
            s_format (str):
                case-insensitive file format (eg, yaml, json, txt, py...)

            x_parser (typing.Callable):
                function returning a dict based for a file ending in s_format
        """
        _D_PARSERS[s_format] = x_parser

    def register_transformer(self, x_check, x_transform):
        self._XAA_TRANSFORMERS.append((x_check, x_transform))


def RG_excepthook(type_, s_description, tb, s_path=__file__):
    """Custom except hook to more shortened stacktrace

    If an exception is raised in this module, the stacktrace removes the parts inside
    this module. This is mostly meant to make the Incidents easier to debug

    Args:
        type_ (type):
            exception type

        s_description (str):
            the text of the exception

        tb (traceback):
            the exceptions traceback object

        s_path (str: __file__):
            the path to the this module on disk
    """

    # Get the stacktrace as a list of frames
    tb_list = traceback.extract_tb(tb)

    if PY3:
        sa_frame_files = [frame.filename for frame in tb_list]
    else:
        sa_frame_files = [frame[0] for frame in tb_list]

    if type_ == RGError and s_path not in sa_frame_files or SHOW_FULL_STACKTRACE:
        return sys.__excepthook__(type_, s_description, tb)

    # build custom stacktrace avoiding the troubles of digging through the ResourceGetter
    # turn on SHOW_FULL_STACKTRACE to get the entire stacktrace
    i_index = max(sa_frame_files.index(s_path)-1, 0)
    frame_mod = next((frame for i, frame in enumerate(tb_list) if i == i_index))

    limited_traceback = traceback.format_list([frame_mod])
    limited_traceback.extend(traceback.format_exception_only(type_, s_description))
    sys.stderr.write(''.join(limited_traceback) + "\n")


def parse_json(path):
    """parse a json path

    Args:
        path (str|pathlib.Path):
            source file

    Returns: dict
    """
    with pathlib.Path(path).open(mode="r") as f:
        return json.load(f)


def parse_yaml(path):
    """parse a yaml path

    Args:
        path (str|pathlib.Path):
            source file

    Returns: dict
    """
    with pathlib.Path(path).open(mode="r") as f:
        return yaml.safe_load(f)


# incidents used throughout this module as replacements for prints/warnings/exceptions
# to change the severity, use INCIDENT.set_severity(MESSAGE|WARNING|ERROR)
INCIDENT_WILDCARD = Incident("Wildcard", MESSAGE)
INCIDENT_EXPECTED_FILE = Incident("ExpectedFile", ERROR)
INCIDENT_NO_EXTENSION = Incident("UnknownExtension", ERROR)


ResourceManager.register_parser("json", parse_json)
if _HAS_YAML:
    ResourceManager.register_parser("yaml", parse_yaml)


if OVERRIDE_EXCEPTHOOK:
    sys.excepthook = RG_excepthook


__all__ = [
    ResourceManager
]


if __name__ == "__main__":
    sep = ":" if os.name == "posix" else ";"
    s_lang = "en_US"

    # set resource paths
    sa_paths = ["resources_test"]
    sa_paths_loc = ["resources_test/street/house/apartment", "resources_test/street/house", "resources_test/street"]
    os.environ["RG_LOCATION_PATH"] = sep.join(sa_paths_loc)

    # get resource managers
    TEXT = ResourceManager("TEXT_*", sa_paths)
    PATHS = ResourceManager("PATHS", sa_paths)
    LOCATION = ResourceManager("LOCATION", "RG_LOCATION_PATH")
    SETTINGS = ResourceManager("SETTINGS", sa_paths)

    # load value
    print("BTN_RELOAD", TEXT("BTN_RELOAD"))

    # load value that is being overridden on different levels
    print("ADDRESS", LOCATION("ADDRESS"))

    # you may wanna test a certain value without altering the config files, you can always add and remove an override
    TEXT.override("BTN_RELOAD", "this value has an override")
    print("BTN_RELOAD (override)", TEXT("BTN_RELOAD"))
    TEXT.remove_override("BTN_RELOAD")
    print("BTN_RELOAD (no override)", TEXT("BTN_RELOAD"))

    # output path based on current configuration, output will be (RG)str
    # PATHS.yaml holds both DEBUG.OUTPUT and RELEASE.OUTPUT
    # if you are using python 3, using f-strings will make this a lot prettier
    s_mode = SETTINGS("MODE")
    s_resource = s_mode + ".OUTPUT"
    s_path = PATHS(s_resource).expand()
    print(s_resource, s_path, type(s_path), isinstance(s_path, basestring))

    # register 'transformer' to transform strings into pathlib.Path objects
    # transformers allow you to pass the queried value through a function
    # 2 functions are used, one to determine if this value should be transformed
    # and one to do the actual transformation
    x_need_to_transform = lambda r: isinstance(r, basestring) and "/" in r
    x_transform = lambda r: pathlib.Path(r)

    PATHS.register_transformer(x_need_to_transform, x_transform)

    # output will now be (RP)Path
    path = PATHS("{MODE}.OUTPUT".format(MODE=s_mode)).expand()
    print(path, type(path), isinstance(path, pathlib.Path))

    # supports any value that can be read by the parse function
    print("VALUE", SETTINGS("VALUE"))
