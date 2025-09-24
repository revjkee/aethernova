// genius-core/code-context/ui/static/js/graph.js

document.addEventListener("DOMContentLoaded", () => {
  const canvas = document.getElementById("graphCanvas");
  const ctx = canvas.getContext("2d");

  let graphData = null;
  let nodeRadius = 18;
  const padding = 20;

  function drawGraph(data) {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    graphData = data;

    if (!graphData?.nodes) return;

    // Layout using simple force-directed placement
    const width = canvas.width;
    const height = canvas.height;
    const angleStep = (2 * Math.PI) / graphData.nodes.length;

    graphData.nodes.forEach((node, i) => {
      const angle = angleStep * i;
      node.x = width / 2 + 200 * Math.cos(angle);
      node.y = height / 2 + 200 * Math.sin(angle);
    });

    // Draw edges
    graphData.edges.forEach(edge => {
      const from = graphData.nodes.find(n => n.id === edge.from);
      const to = graphData.nodes.find(n => n.id === edge.to);

      ctx.beginPath();
      ctx.moveTo(from.x, from.y);
      ctx.lineTo(to.x, to.y);
      ctx.strokeStyle = "#cccccc";
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });

    // Draw nodes
    graphData.nodes.forEach(node => {
      drawNode(node);
    });
  }

  function drawNode(node) {
    ctx.beginPath();
    ctx.arc(node.x, node.y, nodeRadius, 0, 2 * Math.PI);
    ctx.fillStyle = node.type === "function" ? "#4F46E5"
                 : node.type === "class" ? "#059669"
                 : "#F59E0B";
    ctx.fill();
    ctx.strokeStyle = "#333";
    ctx.stroke();

    ctx.fillStyle = "#fff";
    ctx.font = "12px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(node.label, node.x, node.y + 4);
  }

  // API to expose
  window.renderGraph = (symbolGraph) => {
    drawGraph(symbolGraph);
  };

  // Fallback example
  window.renderGraph({
    nodes: [
      { id: "1", label: "MyClass", type: "class" },
      { id: "2", label: "init", type: "function" },
      { id: "3", label: "calculate", type: "function" },
    ],
    edges: [
      { from: "1", to: "2" },
      { from: "1", to: "3" },
    ]
  });
});
