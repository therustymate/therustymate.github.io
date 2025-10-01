document.addEventListener("DOMContentLoaded", () => {
    const carousel = document.getElementById("timeline");
    const frames = carousel.querySelectorAll(".frame");
    let activeIndex = 0;

    function updateCarousel() {
        frames.forEach((frame, i) => {
        frame.classList.remove("active", "prev", "next");
        if (i === activeIndex) frame.classList.add("active");
        else if (i === (activeIndex - 1 + frames.length) % frames.length) frame.classList.add("prev");
        else if (i === (activeIndex + 1) % frames.length) frame.classList.add("next");
        });
    }

    function scrollHandler(e) {
        if (e.deltaY > 0) {
            activeIndex = (activeIndex + 1) % frames.length;
        } else {
            activeIndex = (activeIndex - 1 + frames.length) % frames.length;
        }
        updateCarousel();
    }

    carousel.addEventListener("wheel", scrollHandler);
    updateCarousel();
});
