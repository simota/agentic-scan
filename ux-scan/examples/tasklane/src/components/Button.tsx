export function Button({ variant = "secondary", children, ...props }) {
  return (
    <button className={`btn btn-${variant}`} {...props}>
      <span className="btn-label">{children}</span>
    </button>
  );
}
