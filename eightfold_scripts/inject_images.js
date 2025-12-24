console.log('Inject images start');

// Define media query
const mediaQuery = window.matchMedia('(min-width: 900px)');

// Function to inject images
function injectImages() {
  // Check if images already exist to avoid duplicates
  if (document.getElementById('injected-resume-image-left') || document.getElementById('injected-resume-image-right')) {
    return;
  }

  // Create left image
  const img_left = document.createElement('img');
  img_left.src = 'https://static.vscdn.net/images/careers/demo/netflix/1746474413::main_pcs_left_image';
  img_left.alt = 'Injected Image Left, prepend';
  img_left.style.width = '30%'; // 400 x 272px
  img_left.style.height = 'auto';
  img_left.id = 'injected-resume-image-left';

  // Create right image
  const img_right = document.createElement('img');
  img_right.src = 'https://static.vscdn.net/images/careers/demo/netflix/1746474428::main_pcs_right_image';
  img_right.alt = 'Injected Image Right, append';
  img_right.style.width = '30%'; // 400 x 272px
  img_right.style.height = 'auto';
  img_right.id = 'injected-resume-image-right';

  // Find target and inject images
  const targetElement = document.querySelector('.card-body');
  if (targetElement) {
    targetElement.prepend(img_left);
    targetElement.append(img_right);
  }
}

// Function to remove images
function removeImages() {
  console.log('removing images')
  const img_left = document.getElementById('injected-resume-image-left');
  const img_right = document.getElementById('injected-resume-image-right');

  if (img_left && img_right) {
    img_left.remove();
    img_right.remove();
  }
}

// Check the screen width and inject/remove images accordingly
function checkScreenWidth() {
  if (mediaQuery.matches) {
    injectImages();
  } else {
    removeImages();
  }
}

// Initial check
checkScreenWidth();

// Listen for changes in the screen size
mediaQuery.addEventListener('change', checkScreenWidth);

// MOVE THE RESUME UPLOAD HEADER
const elementToMove = document.querySelector('.upload-resume-header');
const targetContainer = document.querySelector('.upload-resume-container');
if (elementToMove && targetContainer) {
  targetContainer.prepend(elementToMove);
}
