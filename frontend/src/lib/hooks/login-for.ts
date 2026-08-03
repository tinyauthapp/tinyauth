type UseLoginForProps = {
  login_for?: "oidc" | "app";
  params: URLSearchParams;
};

export const useLoginFor = (props: UseLoginForProps): string => {
  const { login_for, params } = props;
  const compiledParams = params.toString() ? "?" + params.toString() : "";

  switch (login_for) {
    case "oidc":
      return "/oidc/authorize" + compiledParams;
    case "app":
      return "/continue" + compiledParams;
    default:
      if (params.get("redirect_uri")) {
        return "/continue" + compiledParams
      }
      return "/logout";
  }
};
