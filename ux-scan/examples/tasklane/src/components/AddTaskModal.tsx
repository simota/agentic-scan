import { useState } from "react";
import { t } from "../i18n";

export function AddTaskModal({ onClose }) {
  const [title, setTitle] = useState("");
  return (
    <div className="modal panel">
      <h2>{t("task.new")}</h2>
      <label htmlFor="task-title">{t("task.titleLabel")}</label>
      <input id="task-title" value={title} onChange={(e) => setTitle(e.target.value)} />
      <button className="btn" onClick={onClose}>{t("common.save")}</button>
    </div>
  );
}
