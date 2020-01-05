let code_mirror = CodeMirror(document.getElementById("sql_editor"), {
    lineNumbers: true,
    mode: "sql"
});

let execute_sql_on_server = (async (sql_request_body) => {
    response = await fetch("/sql",
            {
                method: "POST",
                body: JSON.stringify({request: sql_request_body})
            });
    json = await response.json();
    return json;
});

let build_thead = (async (response_keys) => {
   let thead = document.createElement("thead");
   thead.className = "font-weight-bold";
   let tr = document.createElement("tr");
   response_keys.forEach((key) => {
       let td = document.createElement("td");
       td.appendChild(document.createTextNode(key));
       tr.appendChild(td);
   });
   thead.appendChild(tr);
   return thead;
});

let build_tbody = (async (response_data) => {
    let tbody = document.createElement("tbody");

    response_data.forEach((line) => {
        let tr = document.createElement("tr");
        line.forEach((ceil) => {
            let td = document.createElement("td");
            td.appendChild(document.createTextNode(ceil[1]));
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });
    return tbody;
});

let draw_table_in_div_block = (async (div_block_id, response_keys, response_data) => {
    let parent = document.getElementById(div_block_id);
    parent.innerHTML = "";

    let table = document.createElement("table");
    table.className = "table table-striped";

    let thead = await build_thead(response_keys);
    let tbody = await build_tbody(response_data);

    table.appendChild(thead);
    table.appendChild(tbody);
    parent.appendChild(table);
});

let execute_sql = (async () => {
    let result = await execute_sql_on_server(code_mirror.getValue());
    console.log(result);
    try {
        if (result.status !== "OK") {
            alert(result.status + ': ' + result.message);
            return;
        }

        await draw_table_in_div_block("sql_result", result.keys, result.data);
    } catch {
        alert('Unknown error');
    }
});