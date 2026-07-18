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

// https://www.geeksforgeeks.org/javascript/how-to-check-if-a-string-is-a-valid-ip-address-format-in-javascript
const isIP = (str: string): boolean => {
  const ipv4 =
      /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 =
      /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv4.test(str) || ipv6.test(str) || str.startsWith("[");
}

const trimPeriod = (str: string): string => {
  if(str.lastIndexOf('.') === (str.length - 1)){
    str = str.substring(0, str.length - 1);
  }
  return str
}

export const isTrustedDomain = (
  url: URL,
  appUrl: URL,
  cookieDomain: string,
  subdomainsEnabled: boolean,
): boolean => {
  if (isIP(url.hostname)) {
    return false;
  }

  if (url.port != appUrl.port) {
    return false;
  }

  if (trimPeriod(url.hostname) == trimPeriod(appUrl.hostname)) {
    return true;
  }

  if (!subdomainsEnabled) {
    return false;
  }

  return trimPeriod(url.hostname).endsWith("." + cookieDomain.toLowerCase())
      || trimPeriod(url.hostname) == cookieDomain.toLowerCase();
};
