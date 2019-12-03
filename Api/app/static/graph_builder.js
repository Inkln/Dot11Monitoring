var networks_global = new Map();
var data_global = new Map();

async function start_network(workspace, container_element_id) {
    let container = document.getElementById(container_element_id);
    var options = {
        nodes: {
            shape: "dot",
        },
        groups: {
            ap: {
                size: 25,
                color: "#ffff66"
            },
            client: {
                size: 10,
                color: "#9999ff"
            }
        }
    };
    data = {nodes: new vis.DataSet(), edges: new vis.DataSet()};
    data_global.set(workspace, data);
    networks_global.set(workspace, new vis.Network(container, data, options));

    timer_id = setInterval(() => {
        update_graph(workspace);
    }, 5000);
    setTimeout(() => {
        clearInterval(timer_id);
    }, 600000);
}

async function update_edges(workspace, new_edges) {
    let edges_dataset = data_global.get(workspace).edges;
    edges_dataset.update(new_edges);
}

async function update_nodes(workspace, new_nodes) {
    let nodes_dataset = data_global.get(workspace).nodes;
    nodes_dataset.update(new_nodes);
}

async function fetch_graph(workspace) {
    response = await fetch("/get_graph",
        {
            method: "POST",
            body: JSON.stringify({ workspace: workspace })
        });
    json = await response.json();
    return json.data;
}

async function update_graph(workspace) {
    graph_structure = await fetch_graph(workspace);
    await Promise.all([
        update_nodes(workspace, graph_structure.nodes),
        update_edges(workspace, graph_structure.edges)
    ]);
}
window.addEventListener("load", () => {
   start_network("dev_space", "network-graph");
});
//*/
