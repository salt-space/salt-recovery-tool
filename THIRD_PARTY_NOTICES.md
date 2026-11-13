# Third-party notices

The MIT licence in `LICENSE` covers Salt Recovery Tool's own source code.
Dependencies retain their respective licences and copyright notices; they are
not relicensed by the root MIT file. Distribution and use of dependencies may
also be governed by a separate agreement with their owners.

## Silence Laboratories

This application uses the following unmodified dependencies:

| Component | Pinned version | Upstream licence text |
| --- | --- | --- |
| `sl-dkls23` | `20f748e0681666a7032358dd5ba3336185260e7e` | [Licence](licenses/sl-dkls23-LICENSE.txt) |
| `sl-mpc-mate` | `1.0.0-beta` | [Licence](licenses/sl-mpc-mate-LICENSE.txt) |

These dependencies are licensed under the Silence Laboratories License
Agreement, Copyright © Silence Laboratories Pte. Ltd. All Rights Reserved.
Their bundled upstream licence texts contain non-commercial-use conditions.
The recovery tool's MIT declaration does not override those conditions or
extend the rights granted by a separate redistribution agreement.

Salt Recovery Tool is independently developed; the inclusion of these
components does not imply endorsement by Silence Laboratories.

Installers include these notices as application resources. Published releases
also include `THIRD_PARTY_LICENSES.zip` with these notices and
licence texts. The pinned dependency source and notices can also be retrieved
using the entries in `Cargo.lock`. Other Rust and JavaScript dependencies are
identified in `Cargo.lock` and `package-lock.json` and retain their own licences.
