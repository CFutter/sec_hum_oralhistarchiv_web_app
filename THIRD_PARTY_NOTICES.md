# Third-party notices

The application is licensed under the [MIT license](LICENSE). Its bundled fonts
and password data retain their own terms below. The distribution's SPDX license
expression is `MIT AND OFL-1.1`: installing the distribution includes both the
MIT application and the OFL fonts. This does not relicense the fonts as MIT.

## Source Sans 3 fonts

The four static Latin WOFF2 files in `src/app/static/fonts/` are Source Sans 3
version **3.052**, distributed by Google Fonts in normal/italic weights 400 and
600. The `v19` portion of their local filenames is a distribution label, not the
embedded font version. Their embedded copyright notice is:

> © 2023 Adobe (http://www.adobe.com/), with Reserved Font Name ‘Source’

These fonts are licensed under the **SIL Open Font License 1.1**; see the
[complete, unmodified license](src/app/static/fonts/OFL.txt). That upstream
license retains its 2010–2022 Adobe copyright header and Reserved Font Name
`Source`. Preserve both that license and the embedded 2023 notice when
redistributing these assets. The license's font modification/name requirements
continue to apply.

License source: [Adobe Source Sans 3.052R, commit
`ed1808970eb3c7301c9a523bee26473ba0bb62fa`](https://github.com/adobe-fonts/source-sans/blob/ed1808970eb3c7301c9a523bee26473ba0bb62fa/LICENSE.md).
The bundled files were compared byte for byte with these official Google Fonts
v19 distributions on 22 October 2026:

| Bundled filename | Upstream bytes | SHA-256 |
|---|---|---|
| `source-sans-3-v19-latin-600.woff2` | [Google Fonts](https://fonts.gstatic.com/s/sourcesans3/v19/nwpBtKy2OAdR1K-IwhWudF-R9QMylBJAV3Bo8Kxm7GEK9Cs.woff2) | `14527d193b0e30bc32ef931549a246cdfd286573bb12869b7e052b8101a39d38` |
| `source-sans-3-v19-latin-600italic.woff2` | [Google Fonts](https://fonts.gstatic.com/s/sourcesans3/v19/nwpDtKy2OAdR1K-IwhWudF-R3woAa8opPOrG97lwqGdJxCkSmg.woff2) | `0bc8ce4e6871854cded2a0294bf539b1c2ad6e2d68d5a0897b083955e0e51cc1` |
| `source-sans-3-v19-latin-italic.woff2` | [Google Fonts](https://fonts.gstatic.com/s/sourcesans3/v19/nwpDtKy2OAdR1K-IwhWudF-R3woAa8opPOrG97lwqLlOxCkSmg.woff2) | `3c230c03425a2866e4b57954f3173fc149dba2634e9ee32c681b41d96c7f06fe` |
| `source-sans-3-v19-latin-regular.woff2` | [Google Fonts](https://fonts.gstatic.com/s/sourcesans3/v19/nwpBtKy2OAdR1K-IwhWudF-R9QMylBJAV3Bo8Ky462EK9Cs.woff2) | `0f73f35e08cde0a2f10c109c6e01d71459d97e4099ecd9a50f1b6c0209e4de2b` |

## SecLists common-password data

`src/app/services/data/common_passwords.txt` contains the 10,000-line
`Passwords/Common-Credentials/10k-most-common.txt` list from SecLists. It is
used locally to reject common passwords; the file is data, not application code.

Copyright (c) 2018 Daniel Miessler. Licensed under the **MIT license**; retain the
[complete notice and permission text](src/app/services/data/SECLISTS-LICENSE.txt).
The bundled list was verified byte for byte against [SecLists commit
`a3416ba7062a1bc2ec6b0fe76eac7ee16c80521b`](https://github.com/danielmiessler/SecLists/blob/a3416ba7062a1bc2ec6b0fe76eac7ee16c80521b/Passwords/Common-Credentials/10k-most-common.txt)
on 22 October 2026. The notice comes from the same revision's
[LICENSE](https://github.com/danielmiessler/SecLists/blob/a3416ba7062a1bc2ec6b0fe76eac7ee16c80521b/LICENSE).

SHA-256: `4adb3f0afb4a10cf19ebe48d8c69a46f934bbc8d77c694c210564f9583e7f4ba`.

## Documentation renderer and installed dependencies

The documentation uses `mkdocs-mermaid2-plugin` 1.2.3. With the current
`mkdocs.yaml` configuration, that plugin loads **Mermaid 10.4.0** from
`https://unpkg.com/mermaid@10.4.0/dist/mermaid.esm.min.mjs` in generated pages
that need it. Mermaid is MIT-licensed; its
[upstream license](https://github.com/mermaid-js/mermaid/blob/v10.4.0/LICENSE)
retains the applicable copyright and permission terms. This renderer is a
third-party browser resource of the generated documentation, rather than a
vendored application JavaScript file. Review its hosting, version and license
again when publishing the documentation or changing the plugin/configuration.

Python dependencies are resolved in `uv.lock`; they retain their respective
licenses and notices in installed distributions and the release wheelhouse.
This file records the identified bundled assets and documentation renderer;
it is not an exhaustive dependency license inventory or a software bill of
materials. Final dependency/license evidence remains part of publication
acceptance.
