var networks_global = new Map();
var data_global = new Map();

let start_network = (async (workspace, container_element_id) => {
    let container = document.getElementById(container_element_id);
    let options = {
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

    update_graph(workspace);
    timer_id = setInterval(() => {
        update_graph(workspace);
    }, 5000);
    setTimeout(() => {
        clearInterval(timer_id);
    }, 600000);
});

let schedule = (async (callback, timeout) => {
    callback();
    setTimeout(() => {}, timeout).then(
        () => { schedule(callback, timeout); }
    );
});

let fetch_graph = (async (workspace) => {
        response = await fetch("/get_graph",
            {
                method: "POST",
                body: JSON.stringify({workspace: workspace})
            });
        json = await response.json();
        return json.data;
    });

let update_graph = (async (workspace) => {
    graph_structure = await fetch_graph(workspace);
    await Promise.all([
        (async (new_edges) => {
            data_global.get(workspace).edges.update(new_edges);
        })(graph_structure.edges),
        (async (new_nodes) => {
            data_global.get(workspace).nodes.update(new_nodes);
        })(graph_structure.nodes)
    ]);
});

window.addEventListener("load", () => {
    start_network("dev_space", "network-graph");
});
//*/
