document.addEventListener("DOMContentLoaded", async (e) => {
    let baseURL = "https://localhost/"
    let alert = document.getElementById("alert")
    let decryptBtn = document.getElementById("decryptBtn")
    alert.style.display = "none"
    let index = -1

    await setTables()


    async function setTables() {
        let tbodyMy = document.getElementById("tbodyMy")
        let tbodyPub = document.getElementById("tbodyPub")
        let tbodyFile = document.getElementById("tbodyFiles")
        let tbodyIps = document.getElementById("tbodyIps")
        let title = document.getElementById("title")
        let body = document.getElementById("body")
        let password = document.getElementById("password")

        try {
            let res = await getNotes()
            let notes = res["notes"]
            notes.forEach((element) => {
                let note = JSON.parse(element)

                let newRow = tbodyMy.insertRow()

                let newCell = newRow.insertCell()
                let text = document.createTextNode(note["title"])
                newCell.appendChild(text)

                newCell = newRow.insertCell()
                let btn = document.createElement("a")
                btn.setAttribute("class", "btn btn-primary")
                text = document.createTextNode("Preview")
                btn.appendChild(text)
                newCell.appendChild(btn)

                btn.addEventListener("click", (e) => {
                    e.preventDefault()
                    index = note["id"]
                    body.innerText = ""
                    title.setAttribute("value", note["title"])
                    password.disable = false
                })
            })

            let pubRes = await getPublicNotes()
            notes = pubRes["notes"]
            notes.forEach((element) => {
                let note = JSON.parse(element)

                let newRow = tbodyPub.insertRow()

                let newCell = newRow.insertCell()
                let text = document.createTextNode(note["title"])
                newCell.appendChild(text)

                newCell = newRow.insertCell()
                let btn = document.createElement("a")
                btn.setAttribute("class", "btn btn-primary")
                text = document.createTextNode("Preview")
                btn.appendChild(text)
                newCell.appendChild(btn)

                btn.addEventListener("click", (e) => {
                    e.preventDefault()
                    index = note["id"]
                    body.innerText = ""
                    title.setAttribute("value", note["title"])
                    let text = document.createTextNode(note["body"])
                    body.appendChild(text)
                    password.disable = true
                })
            })

            let fileRes = await getFileNames()
            let files = fileRes["files"]
            files.forEach((element) => {
                let file = JSON.parse(element)

                let newRow = tbodyFile.insertRow()

                let newCell = newRow.insertCell()
                let text = document.createTextNode(file["name"])
                newCell.appendChild(text)
            })

            let ipsRes = await getIps()
            let ips = ipsRes["ips"]
            ips.forEach((element) => {
                let ip = JSON.parse(element)

                let newRow = tbodyIps.insertRow()

                let newCell = newRow.insertCell()
                let text = document.createTextNode(ip["ip"])
                newCell.appendChild(text)
            })
        } catch (e) {
            console.log(e)
        }
    }

    function check_field(password) {
        if (!/^[a-zA-Z0-9!@#$%&*]+$/.test(password)) {
            throw "Wrong password format"
        }
    }

    decryptBtn.addEventListener("click", async (e) => {
        e.preventDefault()
        let bodyNote = document.getElementById("body")
        let passwordInput = document.getElementById("password")
        try {
            if (index === -1) {
                throw "You need to choose note"
            }
            let password = passwordInput.value
            check_field(password)
            let formData = new FormData()
            formData.append("password", password)
            formData.append("id", index)
            let res = await decryptNote(formData)
            bodyNote.innerText = ''
            let text = document.createTextNode(res["message"])
            bodyNote.appendChild(text)
            passwordInput.value = ''
            alert.style.display = "none"
        } catch (e) {
            let getSpan = document.getElementById("alertR")
            if (getSpan !== null) {
                alert.removeChild(getSpan)
            }
            let span = document.createElement("span")
            span.setAttribute("id", "alertR")
            let text = document.createTextNode(e)
            span.appendChild(text)
            alert.appendChild(span)
            passwordInput.value = ''
            alert.style.display = "block"
        }

    })

    async function getNotes() {
        let requestURL = baseURL + "notes/"
        let requestParam = {
            method: "GET",
            redirect: "follow",
        };

        let res = await fetch(requestURL, requestParam)
        if (res.status === 200) {
            return await res.json()
        } else {
            throw "Something went wrong"
        }
    }

    async function getPublicNotes() {
        let requestURL = baseURL + "public/"
        let requestParam = {
            method: "GET",
            redirect: "follow",
        };

        let res = await fetch(requestURL, requestParam)
        if (res.status === 200) {
            return await res.json()
        } else {
            throw "Something went wrong"
        }
    }

    async function getFileNames() {
        let requestURL = baseURL + "file/"
        let requestParam = {
            method: "GET",
            redirect: "follow",
        };

        let res = await fetch(requestURL, requestParam)
        if (res.status === 200) {
            return await res.json()
        } else {
            throw "Something went wrong"
        }
    }


    async function getIps() {
        let requestURL = baseURL + "ips/"
        let requestParam = {
            method: "GET",
            redirect: "follow",
        };

        let res = await fetch(requestURL, requestParam)
        if (res.status === 200) {
            return await res.json()
        } else {
            throw "Something went wrong"
        }
    }

    async function decryptNote(formData) {
        let requestURL = baseURL + "decrypt/"
        let requestParam = {
            method: "POST",
            body: formData,
            redirect: "follow",
        };

        let res = await fetch(requestURL, requestParam)
        if (res.status === 200) {
            return await res.json()
        } else {
            throw "Something went wrong"
        }
    }
})