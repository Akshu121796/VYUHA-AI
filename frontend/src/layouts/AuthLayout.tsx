import React from "react";
import { Outlet } from "react-router-dom";

export function AuthLayout() {
  return (
    <div className="min-h-screen w-full overflow-x-hidden bg-background select-none">
      <Outlet />
    </div>
  );
}

export default AuthLayout;
