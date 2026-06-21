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
  subdomainsEnabled: boolean,
): IuseRedirectUri => {
  let isValid = false;
  let isTrusted = false;
  let isAllowedProto = false;
  let isHttpsDowngrade = false;

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

  if (url.hostname == cookieDomain) {
    isTrusted = true;
  }

  if (subdomainsEnabled && url.hostname.endsWith("." + cookieDomain)) {
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
