type UseLoginForProps = {
  login_for?: "oidc" | "app";
  compiledParams: string;
};

export const useLoginFor = (props: UseLoginForProps): string => {
  const { login_for, compiledParams } = props;

  switch (login_for) {
    case "oidc":
      return "/oidc/authorize" + compiledParams;
    case "app":
      return "/continue" + compiledParams;
    default:
      return "/logout";
  }
};
