type IuseRedirectUri = {
  url?: URL;
  valid: boolean;
  trusted: boolean;
  allowedProto: boolean;
  httpsDowngrade: boolean;
};

export const useRedirectUri = (
  redirect_uri: string | undefined,
  cookieDomain: string,
  appUrl: string,
  subdomainsEnabled: boolean,
): IuseRedirectUri => {
  let isValid = false;
  let isTrusted = false;
  let isAllowedProto = false;
  let isHttpsDowngrade = false;

  let appUrlObj: URL;

  try {
    appUrlObj = new URL(appUrl);
  } catch {
    return {
      valid: isValid,
      trusted: isTrusted,
      allowedProto: isAllowedProto,
      httpsDowngrade: isHttpsDowngrade,
    };
  }

  if (!redirect_uri) {
    return {
      valid: isValid,
      trusted: isTrusted,
      allowedProto: isAllowedProto,
      httpsDowngrade: isHttpsDowngrade,
    };
  }

  let url: URL;

  try {
    url = new URL(redirect_uri);
  } catch {
    return {
      valid: isValid,
      trusted: isTrusted,
      allowedProto: isAllowedProto,
      httpsDowngrade: isHttpsDowngrade,
    };
  }

  isValid = true;

  if (isTrustedDomain(url, appUrlObj, cookieDomain, subdomainsEnabled)) {
    isTrusted = true;
  }

  if (url.protocol == "http:" || url.protocol == "https:") {
    isAllowedProto = true;
  }

  if (window.location.protocol == "https:" && url.protocol == "http:") {
    isHttpsDowngrade = true;
  }

  return {
    url,
    valid: isValid,
    trusted: isTrusted,
    allowedProto: isAllowedProto,
    httpsDowngrade: isHttpsDowngrade,
  };
};

// ported from internal/controller/oauth_controller.go
const getEffectivePort = (url: URL): string => {
  if (url.port) {
    return url.port;
  }

  if (url.protocol == "https:") {
    return "443";
  }

  return "80";
};

export const isTrustedDomain = (
  url: URL,
  appUrl: URL,
  cookieDomain: string,
  subdomainsEnabled: boolean,
): boolean => {
  if (url.protocol != appUrl.protocol) {
    return false;
  }

  if (getEffectivePort(url) != getEffectivePort(appUrl)) {
    return false;
  }

  if (url.hostname == appUrl.hostname) {
    return true;
  }

  if (!subdomainsEnabled) {
    return false;
  }

  if (url.hostname.endsWith("." + cookieDomain.toLowerCase())) {
    return true;
  }

  return false;
};
