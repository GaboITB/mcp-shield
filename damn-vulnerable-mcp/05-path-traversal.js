// DAMN VULNERABLE MCP #05 — Path Traversal
// INTENTIONALLY VULNERABLE — security scanner test target.
// Expected: path_traversal (HIGH)
// DO NOT use in production. DO NOT run this server.

const fs = require("fs");
const path = require("path");
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");

const server = new Server({ name: "vuln-path-mcp", version: "1.0.0" }, {
  capabilities: { tools: {} }
});

server.setRequestHandler("tools/call", async (request) => {
  const args = request.params.arguments;

  // VULN 1: fs.readFileSync with user-controlled path (HIGH)
  if (request.params.name === "read_file") {
    const data = fs.readFileSync(req.params.file);
    return { content: [{ type: "text", text: data.toString() }] };
  }

  // VULN 2: fs.writeFile with user path
  if (request.params.name === "write_file") {
    fs.writeFileSync(req.body.path, req.body.content);
    return { content: [{ type: "text", text: "Written" }] };
  }

  // VULN 3: fs.open with user input
  if (request.params.name === "open_file") {
    const fd = fs.openSync(req.params.file, "r");
    return { content: [{ type: "text", text: "Opened" }] };
  }

  // VULN 4: fs.stat with user path
  if (request.params.name === "file_info") {
    const stat = fs.statSync(req.query.path);
    return { content: [{ type: "text", text: JSON.stringify(stat) }] };
  }

  // VULN 5: fs.symlink with user-controlled target
  if (request.params.name === "create_link") {
    fs.symlinkSync(req.body.target, req.body.link);
    return { content: [{ type: "text", text: "Symlink created" }] };
  }

  // VULN 6: fs.rename with user paths
  if (request.params.name === "move_file") {
    fs.renameSync(req.params.oldPath, req.params.newPath);
    return { content: [{ type: "text", text: "Moved" }] };
  }

  // VULN 7: fs.copyFile with user paths
  if (request.params.name === "copy_file") {
    fs.copyFileSync(req.body.src, req.body.dest);
    return { content: [{ type: "text", text: "Copied" }] };
  }

  // VULN 8: fs.promises with user path
  if (request.params.name === "async_read") {
    const data = await fs.promises.readFile(req.params.file);
    return { content: [{ type: "text", text: data.toString() }] };
  }

  // VULN 9: res.sendFile with user-controlled filename
  if (request.params.name === "serve_file") {
    res.sendFile(req.params.filename);
    return { content: [{ type: "text", text: "Served" }] };
  }

  // VULN 10: path.join does NOT prevent traversal
  if (request.params.name === "read_document") {
    const filePath = path.join("/safe/dir", req.query.path);
    // path.join("base", "../../etc/passwd") = "/etc/passwd"
    const data = fs.readFileSync(filePath);
    return { content: [{ type: "text", text: data.toString() }] };
  }
});

server.setRequestHandler("tools/list", async () => ({
  tools: [
    { name: "read_file", description: "Read a file", inputSchema: { type: "object", properties: { file: { type: "string" } }, required: ["file"] } },
    { name: "write_file", description: "Write a file", inputSchema: { type: "object", properties: { path: { type: "string" }, content: { type: "string" } }, required: ["path", "content"] } },
    { name: "open_file", description: "Open a file descriptor", inputSchema: { type: "object", properties: { file: { type: "string" } }, required: ["file"] } },
    { name: "file_info", description: "Get file info", inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] } },
    { name: "create_link", description: "Create a symlink", inputSchema: { type: "object", properties: { target: { type: "string" }, link: { type: "string" } }, required: ["target", "link"] } },
    { name: "move_file", description: "Move a file", inputSchema: { type: "object", properties: { oldPath: { type: "string" }, newPath: { type: "string" } }, required: ["oldPath", "newPath"] } },
    { name: "copy_file", description: "Copy a file", inputSchema: { type: "object", properties: { src: { type: "string" }, dest: { type: "string" } }, required: ["src", "dest"] } },
    { name: "async_read", description: "Read file async", inputSchema: { type: "object", properties: { file: { type: "string" } }, required: ["file"] } },
    { name: "serve_file", description: "Serve a file", inputSchema: { type: "object", properties: { filename: { type: "string" } }, required: ["filename"] } },
    { name: "read_document", description: "Read a document", inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] } },
  ]
}));
