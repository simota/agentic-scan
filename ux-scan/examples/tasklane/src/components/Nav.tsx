import { NavLink } from "react-router-dom";

export function Nav() {
  return (
    <nav aria-label="Main">
      <NavLink to="/">Tasks</NavLink>
      <NavLink to="/settings">Settings</NavLink>
    </nav>
  );
}
