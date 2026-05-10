import { render } from "solid-js/web";
import { App } from "./ui/App";

const root = document.getElementById("root");
if (!root) throw new Error("#root not found");
render(() => <App />, root);
