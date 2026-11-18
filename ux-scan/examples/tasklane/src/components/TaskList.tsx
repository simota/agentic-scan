import { useEffect, useState } from "react";
import { Trash2 } from "lucide-react";
import { api } from "../api";

export function TaskList() {
  const [tasks, setTasks] = useState([]);
  useEffect(() => {
    fetch("/api/tasks").then((r) => r.json()).then(setTasks);
  }, []);
  return (
    <ul>
      {tasks.map((task) => (
        <li key={task.id} className="card">
          <img src={task.assignee.avatar} className="avatar" />
          <div className="task-title" onClick={() => api.open(task.id)}>{task.title}</div>
          <button className="icon-btn" onClick={() => api.remove(task.id)}>
            <Trash2 />
          </button>
        </li>
      ))}
    </ul>
  );
}
