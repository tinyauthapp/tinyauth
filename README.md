<div align="center">
    <img alt="Tinyauth" title="Tinyauth" width="96" src="assets/logo-rounded.png">
    <h1>Tinyauth</h1>
    <p>The tiniest authentication and authorization server you have ever seen.</p>
</div>

<div align="center">
    <img alt="License" src="https://img.shields.io/github/license/tinyauthapp/tinyauth">
    <img alt="Release" src="https://img.shields.io/github/v/release/tinyauthapp/tinyauth">
    <img alt="Issues" src="https://img.shields.io/github/issues/tinyauthapp/tinyauth">
    <img alt="Tinyauth CI" src="https://github.com/tinyauthapp/tinyauth/actions/workflows/ci.yml/badge.svg">
    <a title="Crowdin" target="_blank" href="https://crowdin.com/project/tinyauth"><img src="https://badges.crowdin.net/tinyauth/localized.svg"></a>
    <a href="https://scorecard.dev/viewer/?uri=github.com/tinyauthapp/tinyauth" target="_blank" title="OpenSSF Scorecard">
      <img src="https://api.scorecard.dev/projects/github.com/tinyauthapp/tinyauth/badge">
    </a>
</div>

<br />

Tinyauth is the simplest and tiniest authentication and authorization server you have ever seen. It is designed to both work as an authentication middleware for your apps, offering support for OAuth, LDAP and access-controls, and as a standalone authentication server. It supports all the popular proxies like Traefik, Nginx and Caddy.

![Screenshot](assets/screenshot.png)

> [!WARNING]
> Tinyauth is in active development and configuration may change often. Please make sure to carefully read the release notes before updating.

> [!NOTE]
> This is the main development branch. For the latest stable release, see the [documentation](https://tinyauth.app) or the latest stable tag.

> [!NOTE]
> Tinyauth is in the process of migrating to the new [tinyauthapp](https://github.com/tinyauthapp) organization. The organization **is official** and it will host all of the Tinyauth related repositories in the future.

## Getting Started

You can get started with Tinyauth by following the guide in the [documentation](https://tinyauth.app/docs/getting-started). There is also an available [docker-compose](./docker-compose.example.yml) file that has Traefik, Whoami and Tinyauth to demonstrate its capabilities (keep in mind that this file lives in the development branch so it may have updates that are not yet released).

## Demo

If you are still not sure if Tinyauth suits your needs you can try out the [demo](https://demo.tinyauth.app). The default username is `user` and the default password is `password`.

## Documentation

You can find documentation and guides on all of the available configuration of Tinyauth in the [website](https://tinyauth.app).

If you wish to contribute to the documentation head over to the [repository](https://github.com/tinyauthapp/docs).

## Discord

Tinyauth has a [Discord](https://discord.gg/eHzVaCzRRd) server. Feel free to hop in to chat about self-hosting, homelabs and of course Tinyauth. See you there!

## Contributing

All contributions to the codebase are welcome! If you have any free time, feel free to pick up an [issue](https://github.com/tinyauthapp/tinyauth/issues) or add your own missing features. Make sure to check out the [contributing guide](./CONTRIBUTING.md) for instructions on how to get the development server up and running.

## Localization

If you like, you can help translate Tinyauth into more languages by visiting the [Crowdin](https://crowdin.com/project/tinyauth) page.

## License

Tinyauth is licensed under the GNU General Public License v3.0. TL;DR — You may copy, distribute and modify the software as long as you track changes/dates in source files. Any modifications to or software including (via compiler) GPL-licensed code must also be made available under the GPL along with build & install instructions. For more information about the license check the [license](./LICENSE) file.

## Sponsors

A big thank you to the following people for providing me with more coffee:

<!-- sponsors --><a href="https://github.com/erwinkramer"><img src="https:&#x2F;&#x2F;github.com&#x2F;erwinkramer.png" width="64px" alt="User avatar: erwinkramer" /></a>&nbsp;&nbsp;<a href="https://github.com/nicotsx"><img src="https:&#x2F;&#x2F;github.com&#x2F;nicotsx.png" width="64px" alt="User avatar: nicotsx" /></a>&nbsp;&nbsp;<a href="https://github.com/SimpleHomelab"><img src="https:&#x2F;&#x2F;github.com&#x2F;SimpleHomelab.png" width="64px" alt="User avatar: SimpleHomelab" /></a>&nbsp;&nbsp;<a href="https://github.com/jmadden91"><img src="https:&#x2F;&#x2F;github.com&#x2F;jmadden91.png" width="64px" alt="User avatar: jmadden91" /></a>&nbsp;&nbsp;<a href="https://github.com/tribor"><img src="https:&#x2F;&#x2F;github.com&#x2F;tribor.png" width="64px" alt="User avatar: tribor" /></a>&nbsp;&nbsp;<a href="https://github.com/eliasbenb"><img src="https:&#x2F;&#x2F;github.com&#x2F;eliasbenb.png" width="64px" alt="User avatar: eliasbenb" /></a>&nbsp;&nbsp;<a href="https://github.com/afunworm"><img src="https:&#x2F;&#x2F;github.com&#x2F;afunworm.png" width="64px" alt="User avatar: afunworm" /></a>&nbsp;&nbsp;<a href="https://github.com/chip-well"><img src="https:&#x2F;&#x2F;github.com&#x2F;chip-well.png" width="64px" alt="User avatar: chip-well" /></a>&nbsp;&nbsp;<a href="https://github.com/Lancelot-Enguerrand"><img src="https:&#x2F;&#x2F;github.com&#x2F;Lancelot-Enguerrand.png" width="64px" alt="User avatar: Lancelot-Enguerrand" /></a>&nbsp;&nbsp;<a href="https://github.com/allgoewer"><img src="https:&#x2F;&#x2F;github.com&#x2F;allgoewer.png" width="64px" alt="User avatar: allgoewer" /></a>&nbsp;&nbsp;<a href="https://github.com/NEANC"><img src="https:&#x2F;&#x2F;github.com&#x2F;NEANC.png" width="64px" alt="User avatar: NEANC" /></a>&nbsp;&nbsp;<a href="https://github.com/ax-mad"><img src="https:&#x2F;&#x2F;github.com&#x2F;ax-mad.png" width="64px" alt="User avatar: ax-mad" /></a>&nbsp;&nbsp;<a href="https://github.com/stegratech"><img src="https:&#x2F;&#x2F;github.com&#x2F;stegratech.png" width="64px" alt="User avatar: stegratech" /></a>&nbsp;&nbsp;<!-- sponsors -->

## Acknowledgements

- **Freepik** for providing the police hat and badge.
- **Renee French** for the original gopher logo.
- **Coderabbit AI** for providing free AI code reviews.
- **Syrhu** for providing the background image of the app.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=tinyauthapp/tinyauth&type=Date)](https://www.star-history.com/#tinyauthapp/tinyauth&Date)
