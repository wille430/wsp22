const setup_ws = () => {
  const show = ((el) => (msg) => {
    if (msg["type"] == "delete") {
      const messageEles = el.children;

      for (var i = 0; i < messageEles.length; i++) {
        if (messageEles[i].id == msg["id"]) {
          console.log("Removing", messageEles[i]);
          messageEles[i].remove();
        }
        // Do stuff
      }
    } else {
      el.innerHTML =
        el.innerHTML +
        `
        <li class="message" id="${msg["id"]}">
            <span class="message-user">${msg["username"]}</span>
            <span class="message-text">${msg["msg"]}</span>
        </li>
    `;
    }
  })(document.getElementById("msgs"));

  const ws = new WebSocket(
    "ws://" + window.location.host + window.location.pathname + "/messages"
  );

  ws.onmessage = (messageEvent) => {
    const msg = JSON.parse(messageEvent.data);
    show(msg);
  };
};

window.onload = function () {
  setup_ws();
};
