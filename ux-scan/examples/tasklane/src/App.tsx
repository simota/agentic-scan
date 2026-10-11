import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Dashboard } from "./pages/Dashboard";
import { Settings } from "./pages/Settings";
import { Archive } from "./pages/Archive";
import { SignupForm } from "./components/SignupForm";
import { Nav } from "./components/Nav";

export function App() {
  return (
    <BrowserRouter>
      <Nav />
      <main id="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/signup" element={<SignupForm />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/archive" element={<Archive />} />
        </Routes>
      </main>
    </BrowserRouter>
  );
}
