// Superseded by Button.tsx; kept until the settings page migrates.
export default function OldButton({ text, onPress }: { text: string; onPress: () => void }) {
  return (
    <div className="btn btn-old" onClick={onPress}>
      {text}
    </div>
  );
}
