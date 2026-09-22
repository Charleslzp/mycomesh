// Package versions are kept in one runtime module so every executable reports
// the same version as the package metadata that ships it.
export const CONSUMER_RELEASE_VERSION = "0.1.52";
export const PROVIDER_RELEASE_VERSION = "0.1.38";

// Provider release pins are intentionally unbound in the source tree. The
// release candidate builder injects the commit and immutable OCI digest into a
// temporary Provider package after the image has been published. Keeping these
// values null prevents a source checkout from pretending that a not-yet-built
// image belongs to the current source.
export const PROVIDER_RELEASE_SOURCE_COMMIT = null;
export const PROVIDER_RELEASE_IMAGE = null;
