import React, { Component, ErrorInfo, ReactNode } from "react";
import { ErrorPage } from "../pages/Error/ErrorPage";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Uncaught error in VYUHA.AI UI:", error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <ErrorPage 
          error={this.state.error} 
          resetError={() => this.setState({ hasError: false, error: null })} 
        />
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
