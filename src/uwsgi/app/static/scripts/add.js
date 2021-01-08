document.addEventListener("DOMContentLoaded", (e) => {
    let baseURL = "https://localhost/"
    let saveBtn = document.getElementById("saveBtn")
    let saveFileBtn = document.getElementById("saveFileBtn")
    let alert = document.getElementById("alert")
    let alertFile = document.getElementById("alertFile")
    alert.style.display = "none"
    alertFile.style.display = "none"

    saveBtn.addEventListener("click", async (e) => {
        e.preventDefault()
        let titleInput = document.getElementById("title")
        let bodyInput = document.getElementById("body")
        let passwordInput = document.getElementById("password")

        function validateFields(title, body, password) {
            if (!/^[a-zA-Z0-9.,!?@%&()\s]+$/.test(title)) {
                throw "Your title is in wrong format"
            }
            if (!/^[a-zA-Z0-9.,!?@%&()\s]+$/.test(body)) {
                throw "Your note is in wrong format"
            }
            if (password !== null && !/^[a-zA-Z0-9!@#$%&*]+$/.test(password)) {
                throw "You can't do that"
            }
        }

        try {
            if (titleInput.value === null && bodyInput.value === null) {
                throw "You need to enter note and title"
            } else {
                let title = titleInput.value
                let body = bodyInput.value
                let password = passwordInput.value.length > 0 ? passwordInput.value : null;
                validateFields(title, body, password);

                let form = document.getElementById("note-form")
                let formData = new FormData(form)
                let result = await saveNote(formData)
                if (result === 201) {
                    window.location.href = "/user/"
                } else {
                    throw "Something went wrong"
                }
            }
        } catch (err) {
            let getSpan = document.getElementById("alertR")
            if (getSpan !== null) {
                alert.removeChild(getSpan)
            }
            let span = document.createElement("span")
            span.setAttribute("id", "alertR")
            let text = document.createTextNode(err)
            span.appendChild(text)
            alert.appendChild(span)
            alert.style.display = "block"
        }
    });

    saveFileBtn.addEventListener("click", async (e) => {
        e.preventDefault()
        let fileInput = document.getElementById("file")

        try {
            if (fileInput.files.length == 0) {
                throw "You need to provide file"
            }
            let fileForm = document.getElementById("file-form")
            let formData = new FormData(fileForm)
            let res = await saveFile(formData)
            if (res !== 201) {
                throw "Something went wrong"
            }
            window.location.href = "/user/"
        } catch (err) {
            let getSpan = document.getElementById("alertF")
            if (getSpan !== null) {
                alertFile.removeChild(getSpan)
            }
            let span = document.createElement("span")
            span.setAttribute("id", "alertF")
            let text = document.createTextNode(err)
            span.appendChild(text)
            alertFile.appendChild(span)
            alertFile.style.display = "block"
        }
    })

    async function saveNote(formData) {
        let requestURL = baseURL + "savenote/"
        let requestParam = {
            method: "POST",
            body: formData,
            redirect: "follow",
        };

        let res = await fetch(requestURL, requestParam)
        return res.status
    }

    async function saveFile(formData) {
        let requestURL = baseURL + "file/"
        let requestParam = {
            method: "POST",
            body: formData,
            redirect: "follow",
        };

        let res = await fetch(requestURL, requestParam)
        return res.status
    }
})
