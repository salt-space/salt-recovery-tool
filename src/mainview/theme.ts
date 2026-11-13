import { createSystem, defaultConfig, defineConfig } from '@chakra-ui/react';

const config = defineConfig({
  theme: {
    tokens: {
      colors: {
        brand: {
          50: { value: '#f1efff' },
          100: { value: '#ded8ff' },
          500: { value: '#5D43F7' },
          600: { value: '#4c34d8' },
          700: { value: '#36239c' },
        },
        bronze: {
          500: { value: '#B89D7E' },
        },
      },
      fonts: {
        body: { value: 'Inter, system-ui, -apple-system, sans-serif' },
        heading: { value: 'Inter, system-ui, -apple-system, sans-serif' },
      },
    },
  },
});

export const system = createSystem(defaultConfig, config);
