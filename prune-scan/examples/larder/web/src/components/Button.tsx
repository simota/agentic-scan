type Props = { label: string; onClick?: () => void };

export default function Button({ label, onClick }: Props) {
  return (
    <button className="btn" type="button" onClick={onClick}>
      {label}
    </button>
  );
}
