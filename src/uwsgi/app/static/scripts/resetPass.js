document.addEventListener("DOMContentLoaded", (e) => {
    let submitBtn = document.getElementById("submit")
    let baseURL = "https://localhost/"

    submitBtn.addEventListener("click",async ev => {
        ev.preventDefault()
        let form = document.getElementById("password-form")
        let formData = new FormData(form)
        let token = document.getElementById("token").value
        try {
            await tokenCreate(formData, token)
            console.log("Changed password")
            setTimeout(1000, (e) => {
                window.location.href = "/"
            })
        } catch (e) {
            console.log(e)
        }
    })

    async function tokenCreate(formData, token) {
        let requestURL = baseURL + "password/" + token
        let requestParam = {
            method: "POST",
            body: formData,
            redirect: "follow",
        };

        let res = await fetch(requestURL, requestParam)
        if (res.status === 200) {
            return res.status
        } else {
            switch (res.status) {
                case 404: throw "Not found";break;
                case 400: throw "No email";break;
                case 403: throw "Forbidden input"; break;
                default: throw "Unexpected error"
            }
        }
    }
})