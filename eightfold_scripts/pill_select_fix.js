/* NETH-175: fixing pill deselection issue START */
function blurUnselectedFocusedPills() {
    const focused = document.activeElement;
    if (focused.classList.contains('pillContainer') && !focused.classList.contains('pillInclude')) {
      console.log('👋 Blurring unselected focused pill:', focused);
      focused.blur();
    }
  }
  
  function handlePills() {
    const pills = document.querySelectorAll('.pillContainer');
    if (pills.length > 0) {
      blurUnselectedFocusedPills();
    }
  }
  
  // Initial wait for pills to appear
  function waitForInitialPills() {
    const pills = document.querySelectorAll('.pillContainer');
    if (pills.length === 0) {
      setTimeout(waitForInitialPills, 300);
    } else {
      console.log('✅ Pills found. Running blur check.');
      handlePills();
    }
  }
  
  // Mutation observer to re-run when DOM changes (e.g. pill reloaded)
  const observer = new MutationObserver(() => {
    handlePills();
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
  
  // Start the wait-and-observe cycle
  waitForInitialPills();
  
/* NETH-175: fixing pill deselection issue END */