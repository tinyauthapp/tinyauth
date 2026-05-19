import { Navigate } from "react-router";
import { useUserContext } from "./context/user-context";

export const App = () => {
  const { auth } = useUserContext();

  if (auth.authenticated) {
    return <Navigate to="/logout" replace />;
  }

  return <Navigate to="/login" replace />;
};
