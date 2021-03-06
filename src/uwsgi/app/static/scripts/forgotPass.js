document.addEventListener("DOMContentLoaded", (e) => {
    let submitBtn = document.getElementById("submit")
    let baseURL = "https://localhost/"

    submitBtn.addEventListener("click",async ev => {
        ev.preventDefault()
        let form = document.getElementById("email-form")
        let formData = new FormData(form)
        try {
            await tokenCreate(formData)
            console.log("Created token")
        } catch (e) {
            console.log(e)
        }
    })

    async function tokenCreate(formData) {
        let requestURL = baseURL + "password/"
        let requestParam = {
            method: "POST",
            body: formData,
            redirect: "follow",
        };

        let res = await fetch(requestURL, requestParam)
        if (res.status === 201) {
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