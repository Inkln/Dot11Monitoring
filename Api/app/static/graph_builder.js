var network = undefined;

async function draw_network_graph(div_id, nodes_input, edges_input) {
    let container = document.getElementById(div_id);
    let data = {
        nodes: nodes_input,
        edges: edges_input
    };
    var options = {
        nodes: {
            shape: "dot",
            scaling: {
                customScalingFunction: function (min, max, total, value) {
                    return value / total;
                },
                min: 5,
                max: 150
            }
        }
    };
    let local_network = new vis.Network(container, data, options);
    return local_network;
}

async function get_network(workspace) {
    const response = await fetch("/get_graph",
        {
            method: "POST",
            body: JSON.stringify({
                workspace: workspace
            })
        });
    const json_result = await response.json();
    if (!response.ok) {
        console.log('Fetch graph failed with non 200 code');
    }
    if (json_result.status != 'ok') {
        console.log('Status is ' + json_result.status)
    }
    graph_structure = json_result.data;

    nodes = graph_structure.nodes;
    edges = graph_structure.edges;



    network = await draw_network_graph("network-graph", nodes, edges);
    // return network;
}

window.addEventListener("load", () => {
   get_network("dev_space");
});
