module.exports = {
	darkMode: 'class',
	content: ['./src/**/*.{html,js,svelte,ts}'],
	theme: {
		extend: {
			screens: {
				'4k': '2048px',
				retina: '2560px',
			},
			opacity: {
				999: '0.999',
			},
			fontSize: {
				display: '5.625rem',
				'display-mobile': '4.4rem',
				body: '1rem',
				'body-large': '1.125rem',
				'body-medium': '0.875rem',
				'body-small': '0.75rem',
				'body-xl': '1.5rem',
				'body-xxl': '1.625rem',
				quote: '2rem',
				overline: '0.875rem',
				'overline-small': '0.75rem',
				caption: '0.875rem',
				'caption-bold': '1rem',
				button: '0.875rem',
				'button-small': '0.675rem',
				link: '1rem',
				'link-small': '0.875rem',
				'link-tiny': '0.75rem',
			},
			margin: {
				'1/2': '0.125rem',
				22: '5.5rem',
				128: '40rem',
			},
			colors: {
				purple: {
					DEFAULT: '#6A49E4',
				},
				cyan: {
					DEFAULT: '#00D3DD',
				},
				blue: {
					350: '#1DA1F2',
					550: '#3A83A3',
				},
				gray: {
					350: '#AAAAAA',
					370: '#A0A4A8',
					650: '#3E3E3E',
					DEFAULT: '#212121',
					'primary-03': '#262626',
				},
			},
			fontFamily: {
				poppins: ['Poppins'],
				nunito: ['Nunito'],
				inter: ['Inter'],
				inconsolata: ['Inconsolata'],
				rajdhani: ['Rajdhani'],
				roboto: ['Roboto'],
			},
			borderRadius: {
				20: '20px',
				40: '40px',
				xl: '50px',
				big: '20px',
				giant: '70px',
				full: '100%',
			},
			minWidth: {
				button: '232px',
			},
			minHeight: {
				256: '50rem',
				'half-screen': '50vh',
				96: '24rem',
			},
			maxHeight: {
				fhd: '62.5rem',
				'screen-9/10': '90vh',
				'screen-7/8': '87.5vh',
				'screen-5/6': '83vh',
				'screen-4/5': '80vh',
				'screen-3/4': '75vh',
				'screen-7/10': '70vh',
				'screen-2/3': '66.6vh',
				'screen-5/8': '62.5vh',
				'screen-3/5': '60vh',
				'screen-1/2': '50vh',
				'screen-2/5': '40vh',
				'screen-3/8': '37.5vh',
				'screen-1/3': '33.3vh',
				'screen-3/10': '30vh',
				'screen-1/4': '25vh',
				'screen-1/5': '20vh',
				'screen-1/6': '16.6vh',
				'screen-1/8': '12.5vh',
				'screen-1/10': '10vh',
			},
			height: {
				100: '26.5rem',
				120: '38.5rem',
				128: '40rem',
				144: '45rem',
				256: '50rem',
				'half-screen': '50vh',
			},
			width: {
				100: '26.5rem',
				120: '38.5rem',
				128: '40rem',
				144: '45rem',
				256: '50rem',
			},
			boxShadow: {
				2: '-59px 27px 63px 0px #000000CC',
			},
		},
		linearBorderGradients: {
			directions: {
				t: 'to top',
				tr: 'to top right',
				r: 'to right',
				br: 'to bottom right',
				b: 'to bottom',
				bl: 'to bottom left',
				l: 'to left',
				tl: 'to top left',
				117: '117deg',
				187: '187.33deg',
				213: '213.5deg',
				209: '209.87deg',
				208: '208.78deg',
			},
			colors: {
				button: ['#04D2CA 30.98%', '#6A49E4 98.42%'],
				'01': ['#13E2BB 32.66%', '#4C49E4 64.17%', '#9363F9 97.71%'],
				'02': ['#3376E7 31.2%', '#976EF1 71.49%'],
				'03': ['#4C49E4 41.05%', '#3376E7 58.35%', '#26F3A8 77.95%'],
				'04': ['#13E2BB 32.66%', '#9363F9 97.71%'],
				'05': ['#14ACB6 31.2%', '#7141D7 71.49%'],
				'06': ['#26F3A8 41.05%', '#3376E7 77.95%'],
				'07': ['#235465 -8.1%', '#8EC95F 50.77%', '#8E63DB 110.89%'],
				'08': ['#9363F9 30.11%', '#E55A54 97.41%'],
				'09': ['#14ACB6 31.2%', '#7141D7 71.49%'],
				10: ['#499DEB 31.2%', '#541D9A 70.86%'],
			},
			background: {
				black: '#000000',
				light: '#0E0E0E',
				gray: '#212121',
				transparent: 'transparent',
			},
		},
		flex: {
			'9/10': '0 90%',
			'7/8': '0 87.5%',
			'5/6': '0 83%',
			'4/5': '0 80%',
			'3/4': '0 75%',
			'7/10': '0 70%',
			'2/3': '0 66.6%',
			'5/8': '0 62.5%',
			'3/5': '0 60%',
			'1/2': '0 50%',
			'2/5': '0 40%',
			'3/8': '0 37.5%',
			'1/3': '0 33.3%',
			'3/10': '0 30%',
			'1/4': '0 25%',
			'1/5': '0 20%',
			'1/6': '0 16.6%',
			'1/8': '0 12.5%',
			'1/10': '0 10%',
		},
	},
};
