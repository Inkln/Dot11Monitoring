var network;
var data_global = new Map();
var workspaces_list = [];
var current_workspace = "";

let init_network = (async (container_element_id) => {
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

    let workspace = undefined;

    workspace = await (async () => {})()
        .then(update_workspaces_list)
        .then(get_selected_workspace);

    data = {nodes: new vis.DataSet(), edges: new vis.DataSet()};
    data_global.set(workspace, data);
    network = new vis.Network(container, data, options);

    update();
    timer_id = setInterval(() => {
        update();
    }, 5000);
    setTimeout(() => {
        clearInterval(timer_id);
    }, 600000);
});

let fetch_graph = (async (workspace) => {
    let url = "/get_graph?workspace=" + encodeURIComponent(workspace);
    let response = await fetch(url);
    let json = await response.json();
    return json.data;
    });

let update_graph = (async (workspace) => {
    graph_structure = await fetch_graph(workspace);
    if (!data_global.has(workspace)) {
        data_global.set(workspace, {nodes: new vis.DataSet(), edges: new vis.DataSet()});
    }
    if (workspace !== current_workspace) {
        network.setData(data_global.get(workspace));
        current_workspace = workspace;
    }
    await Promise.all([
        (async (new_edges) => {
            data_global.get(workspace).edges.update(new_edges);
        })(graph_structure.edges),
        (async (new_nodes) => {
            data_global.get(workspace).nodes.update(new_nodes);
        })(graph_structure.nodes)
    ]);
});

let fetch_workspaces_list = (async() => {
   response = await fetch("/get_workspaces",
            {
                method: "GET"
            });
        json = await response.json();
        return json.data;
});

let update_workspaces_list  = (async () => {
   let actual_workspaces_list = await fetch_workspaces_list();
   let parent = document.getElementById("active_workspace");
   for (const element of actual_workspaces_list) {
       if (!workspaces_list.includes(element)) {
           workspaces_list.push(element);
           let new_option = document.createElement("option");
           new_option.value = element;
           new_option.text = element;
           parent.appendChild(new_option);
       }
   }
});

let get_selected_workspace = (async () => {
   let parent = document.getElementById("active_workspace");
   try {
       return result = parent.options[parent.selectedIndex].value;
   } catch {
       return "undefined_workspace";
   }
});

let update = (async () => {
    return (async () => {})()
        .then(update_workspaces_list)
        .then(get_selected_workspace)
        .then(update_graph);
});

window.addEventListener("load", () => {
    init_network("network-graph");
});
//*/
