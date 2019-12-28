let myCodeMirror = CodeMirror(document.getElementById("sql_editor"), {
    lineNumbers: true,
    mode: "sql"
});

let execute_sql_on_server = (async(sql_request_body) => {
    response = await fetch("/sql",
            {
                method: "POST",
                body: JSON.stringify({request: sql_request_body})
            });
    json = await response.json();
    return json;
});

var execute_sql = (async () => {
    let result = await execute_sql_on_server(myCodeMirror.getValue());
    console.log(result);
});