document.addEventListener("DOMContentLoaded", async (e) => {
    let baseURL = "https://localhost/"
    let alert = document.getElementById("alert")
    alert.style.display = "none"
    let index = -1

    await setTables()

    async function setTables() {
        let tbodyMy = document.getElementById("tbodyMy")
        let tbodyPub = document.getElementById("tbodyPub")
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
                    title.setAttribute("value", note["title"])
                    let text = document.createTextNode(note["body"])
                    body.appendChild(text)
                    password.disable = true
                })
            })
        } catch (e) {
            console.log(e)
        }
    }

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
})