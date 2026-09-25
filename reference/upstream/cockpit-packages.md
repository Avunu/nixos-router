## Cockpit Packages

[Layout of Package Files](https://garrett.github.io/cockpit-website-jekyll/guide/latest/packages.html#package-layout)[Package Manifest](https://garrett.github.io/cockpit-website-jekyll/guide/latest/packages.html#package-manifest)[Package Links and Paths](https://garrett.github.io/cockpit-website-jekyll/guide/latest/packages.html#package-links)[Content Negotiation](https://garrett.github.io/cockpit-website-jekyll/guide/latest/packages.html#package-minified)[Using Cockpit API](https://garrett.github.io/cockpit-website-jekyll/guide/latest/packages.html#package-api)[Bridges for specific tasks](https://garrett.github.io/cockpit-website-jekyll/guide/latest/packages.html#package-bridges)[Replacing an existing package](https://garrett.github.io/cockpit-website-jekyll/guide/latest/packages.html#package-replace)

Cockpit is separated into various packages, each of which brings specific
features and/or code.

### Warning

In addition, any APIs or behavior not explicitly documented here is an
internal API and can be changed at any time.

## Layout of Package Files

A package consists of one or more files placed in a directory or its
subdirectories. It must have a `manifest.json` file and follow
certain naming conventions.

The name of a package is the name of the directory.

The name of the package must be ASCII alphanumeric, and may contain an underscore.
Names of directories and files in the package must consist of ASCII alphanumeric
along with dash, underscore, dot, and comma. No spaces are allowed.

Cockpit uses the data directories from the
[XDG Base Directory\\
Specification](http://standards.freedesktop.org/basedir-spec/basedir-spec-latest.html)
to locate packages. The `$XDG_DATA_DIRS` represents a colon separate list of system data
directories, and `$XDG_DATA_HOME` is a user specific data directory. If the environment
variables are not set, defaults are used, according to the spec. If cockpit has been built with an
alternate `--prefix=/path` then the `$prefix/share/cockpit` is used by
default.

A `cockpit/` subdirectories in any of these data directories is the location where
packages are loaded by Cockpit. If Cockpit finds a package with the same name, in multiple data
directories, then the first one wins. According to the spec the first data directory is
`$XDG_DATA_HOME` and then `$XDG_DATA_DIRS` in order.

This means that, by default the following directories are searched for cockpit packages, and
in this order:

- `~/.local/share/cockpit/`

- `/usr/local/share/cockpit/`

- `/usr/share/cockpit/`


Packages placed in `$XDG_DATA_HOME` are not cached by Cockpit or the web browser.
Other packages are cached aggressively, and are accessed using a checksum of the files in
the packages and their names.

You can use the following command to list the packages installed on a server. You'll note that
it's output may change when you run the command as different users, if there are packages installed
in the user's home directory.

```
$ cockpit-bridge --packages
...
```

To further clarify things, here is an example package called "my-package" and its file layout:

```
/usr/share/cockpit/
    my-package/
        manifest.json
        file.html
        some.js
```

Place or symlink packages in your `~/.local/share/cockpit` directory (or appropriate
`$XDG_DATA_HOME` location) that you would like to modify and develop. System installed
packages should not change while Cockpit is running.

## Package Manifest

Each package has a `manifest.json` file. It is a JSON object. The following
fields may be present in the manifest:

|     |     |
| --- | --- |
| content-security-policy | By default Cockpit serves packages using a strict<br>[Content Security Policy](https://en.wikipedia.org/wiki/Content_Security_Policy),<br>which among other things does not allow inline styles or scripts. This can<br>be overriden on a per-package basis, with this setting.<br>If the overriden content security policy does not contain a `default-src` or<br>`connect-src` these will be added to the policy from the manifest. |
| dashboard | An optional JSON object containing any dashboard items that this package<br>provides. These will be added into the Cockpit user interface on the top bar.<br>Each property on this object is named for the identifier of such an item, and the<br>property value is a JSON object described below. |
| menu | An optional JSON object containing any main menu items that this package<br>provides. These will be added into the Cockpit user interface on the side bar.<br>Each property on this object is named for the identifier of such an item, and the<br>property value is a JSON object described below. |
| name | An optional string that changes the name of the package. Normally<br>packages derive their name from the directory that they are located in. This<br>field overrides that name. |
| priority | An optional number that specifies which package is prefered in cases<br>where there are conflicts. For example given two packages with the same<br>`name` a package is chosen based on its priority. |
| requires | An optional JSON object that contains a `"cockpit"`<br>string version number. The package will only be usable if the Cockpit bridge<br>and javascript base are equal or newer than the given version number. |
| tools | An optional JSON object containing all the tools that this package<br>provides. These will be added into the Cockpit user interface under the 'Tools' menu.<br>Each property on this object is named for the identifier of such a tool, and the<br>property value is a JSON object described below. |
| version | An informational version number for the package. |

Menu items and tools are registered using JSON objects that have the
following properties:

|     |     |
| --- | --- |
| label | The label for the menu item or tool. |
| order | An optional order number to place this menu item or tool. Lower numbers<br>are listed first. |
| path | The relative path to the HTML file within the package that implements<br>the menu item or tool. |

An example manifest.json with some optional properties set:

```
{
  "version": 0,
  "require": {
      "cockpit": "120"
  },
  "tools": {
     "mytool": {
        "label": "My Tool",
        "path": "tool.html"
     }
  }
}
```

A file called `override.json` may be placed next to the manifest.
containing overrides to the information in the manifest. These override files are in the
simple [JSON Merge Patch](https://tools.ietf.org/html/rfc7386) format.

## Package Links and Paths

When referring to files in your package, such as in a hyperlink or a `<style>`
tag or `<script>` tag, simply use a relative path, and refer to the files
in the same directory. When you need to refer to files in another package use a relative link.

For example here's how to include the base `cockpit.js` script in your HTML
from the `latest` package:

```
<script src="../base1/cockpit.js"></script>
```

Do not assume you can link to any file in any other package. Refer to the
[list of API packages](https://garrett.github.io/cockpit-website-jekyll/guide/latest/development.html "Part III. Developer Guide") for those that are
available for use.

## Content Negotiation

In order to support language specific files, gzipped and/or minified data, the
files in a package are loaded using content negotiation logic.

If a file does not exist at the expected path, Cockpit tries to insert
`.min` before its extension. It also tries adding a `.gz`
to both of those file names. If the file is still not found, and the request path has
more than one extension, the second to the last extension is popped off, and the above
process repeats.

This means that for the file `test.de.js` in the package named
`mypackage` the following files would be tried in this order:

```
mypackage/test.de.js
mypackage/test.de.min.js
mypackage/test.de.js.gz
mypackage/test.de.min.js.gz
mypackage/test.js
mypackage/test.min.js
mypackage/test.js.gz
mypackage/test.min.js.gz
```

When packages are loaded from a system directory, Cockpit optimizes the file
system lookups above, by pre-listing the files. This is one of the reasons that
you should never change packages installed to a system directory while Cockpit
is running.

## Using Cockpit API

Cockpit has API available for writing packages. There is no API available
for external callers to invoke via HTTP, REST or otherwise.

API from various packages can be used to implement Cockpit packages. Each package
listed here has some API available for use. Only the API explicitly documented should
be used.

- [API Listing](https://garrett.github.io/cockpit-website-jekyll/guide/latest/development.html "Part III. Developer Guide")


To include javascript from the API, simply load it into your HTML using
a script tag. Alternatively you can use an javascript loader.

## Bridges for specific tasks

On the server side the
`cockpit-bridge` connects
to various system APIs that the front end UI requests it to. There are additional
bridges for specific tasks that the main `cockpit-bridge` cannot
handle. For example tasks that should be carried out with privilege escalation.

These additional bridges can be registered in a `"bridges"` section of a
package's `manifest.json` file. Building such a bridge is a complex tasks, and
we will skip over that here. However it is useful to adjust how these additional bridges
are called, and so we'll look at how they are registered.

An example `manifest.json` with a bridges section:

```
{
  "bridges": [\
    {\
      "match": { "superuser": null },\
      "environ": [ "SUDO_ASKPASS=/usr/bin/my-password-tool" ],\
      "spawn: [ "/usr/bin/sudo", "-n", "cockpit-bridge", "--privileged" ],\
      "problem": "access-denied"\
    }\
  ]
}
```

The bridges are considered in the order they are listed in the array. Use the
`manifest.json``"priority"` field to control order between
packages. The bridges are registered using JSON objects that have the following
properties:

|     |     |
| --- | --- |
| environ | Optional, additional environment variables to pass to the bridge<br>command. |
| match | The `"match"` object describes which channel open command<br>options need to match for a given channel to be handed over to this<br>bridge. |
| problem | If a problem is specified, and this bridge fails to start up then<br>channels will be closed with this problem code. Otherwise later bridges or internal<br>handlers for the channel will be invoked. |
| spawn | The command and arguments to invoke. |

The `spawn` and `environ` values can be dynamically
taken from a matching open command values. When a value in either the `spawn`
or `environ` array contains a named variable wrapped in `${}`,
the variable will be replaced with the value contained in the matching open command.
Only named variables are supported and name can only contain letters, numbers and
the following symbols: `._-`

For example a bridges section like:

```
{
  "bridges": [\
    {\
      "match": { "payload": "example" },\
      "environ": [ "TAG=${tag}" ],\
      "spawn: [ "/example-bridge", "--tag", "${tag}" ],\
      "problem": "access-denied"\
    }\
  ]
}
```

when a open command is received with a payload of `example`
with `tag` value of `tag1`. The following
command will be spawned

```
TAG=tag1 /example-bridge --tag tag1
```

Processes that are reused so if another open command with a "tag" of
`tag1` is received. The open command will be passed to
existing process, rather than spawning a new one. However a open command
with an tag of `tag2` will spawn a new command:

```
TAG=tag2 /example-bridge --tag tag2
```

If you need to include `${}`, as an actual value in your arguments
you can escape it by prefixing it with a `\`

## Replacing an existing package

If the functionality in a package replaces that of another package
then it can replace that package by claiming the same `name` and a
higher `priority`.

For example, a package in the `/usr/share/cockpit/disks`
directory could replace Cockpit's _storage_ package with
a `manifest.json` like this:

```
{
  "version": 0,
  "name": "storage",
  "priority": 10,
  "menu": {
     "index": {
        "label": "Disk Storage",
        "order": 15
     }
  }
}
```

It is also possible to hide or change labels on the menu items of an existing
package by including a `override.json` in that existing package's
directory.

For example an `/usr/share/cockpit/systemd/override.json` could
hide the _Logs_ menu item and move the _Services_
menu item to the top of the menu.

```
{
  "menu": {
    "logs": null,
    "services": {
      "order": -1
    }
  }
}
```