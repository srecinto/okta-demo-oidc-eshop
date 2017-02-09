/*price range*/

if ($.isFunction($('#sl2').slider)) {
 $('#sl2').slider();

	var RGBChange = function() {
	  $('#RGB').css('background', 'rgb('+r.getValue()+','+g.getValue()+','+b.getValue()+')')
	};
}
/*scroll to top*/

$(document).ready(function(){
	handleAuthSession();
	$(function () {
		$.scrollUp({
	        scrollName: 'scrollUp', // Element ID
	        scrollDistance: 300, // Distance from top/bottom before showing element (px)
	        scrollFrom: 'top', // 'top' or 'bottom'
	        scrollSpeed: 300, // Speed back to top (ms)
	        easingType: 'linear', // Scroll to top easing (see http://easings.net/)
	        animation: 'fade', // Fade, slide, none
	        animationSpeed: 200, // Animation in speed (ms)
	        scrollTrigger: false, // Set a custom triggering element. Can be an HTML string or jQuery object
					//scrollTarget: false, // Set a custom target element for scrolling to the top
	        scrollText: '<i class="fa fa-angle-up"></i>', // Text for element, can contain HTML
	        scrollTitle: false, // Set a custom <a> title if required.
	        scrollImg: false, // Set true to use image
	        activeOverlay: false, // Set CSS color to display scrollUp active point, e.g '#00FFFF'
	        zIndex: 2147483647 // Z-Index for the overlay
		});
	});
});

function handleAuthSession() {
  var token_cookie = Cookies.get("token");

  if(token_cookie == "NO_TOKEN")
    Cookies.remove("token");
  else {
    $.getJSON( "https://okta-demo-oidc-eshop-new-recinto.c9users.io/user", function( data ) {
      if(data.active) {
        $("#login").html(data.username);
      } else {
        if(data.redirect_url){
          location.href = data.redirect_url
        } else {
          Cookies.remove("token");
        }
      }
    });
  }
}
