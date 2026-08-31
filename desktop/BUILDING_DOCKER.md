# AccordLock container status

AccordLock Desktop is currently a **source alpha**. No public AccordLock container image is published, and upstream Goose images are not substitutes for this distribution.

The inherited Docker publication workflow is quarantined. It cannot push images. Local container experiments must build the current reviewed source using the same hardened profile documented in the repository README:

```text
--no-default-features --features accordlock-distribution,rustls-tls,system-keyring
```

A CLI container does not include the complete desktop/native-runtime pair and must not be described as the AccordLock product, connected to production credentials, or redistributed as a supported image.

Container publication remains blocked until the runtime boundary is reproducibly packaged, the image and native runtime have linked provenance, credentials have a reviewed container-vault design, and a release owner approves signing, rollback, and update procedures.

AccordLock is derived from [Goose](https://github.com/aaif-goose/goose) and preserves the upstream Apache-2.0 license and attribution.
