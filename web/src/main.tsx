import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import { App } from "@/App";
import { Toaster } from "@/components/ui/toaster";
import { SessionProvider } from "@/session";
import "./index.css";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <SessionProvider>
        <App />
        <Toaster />
      </SessionProvider>
    </BrowserRouter>
  </React.StrictMode>,
);
