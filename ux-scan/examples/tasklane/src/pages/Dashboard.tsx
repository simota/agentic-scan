import { useState } from "react";
import { t } from "../i18n";
import { Button } from "../components/Button";
import { TaskList } from "../components/TaskList";
import { AddTaskModal } from "../components/AddTaskModal";

export function Dashboard() {
  const [adding, setAdding] = useState(false);
  return (
    <div className="layout">
      <aside className="sidebar">
        <h3 className="title">Lists</h3>
      </aside>
      <section>
        <Button variant="primary" onClick={() => setAdding(true)}>{t("task.new")}</Button>
        <Button variant="primary">{t("task.import")}</Button>
        <TaskList />
      </section>
      {adding && <AddTaskModal onClose={() => setAdding(false)} />}
    </div>
  );
}
