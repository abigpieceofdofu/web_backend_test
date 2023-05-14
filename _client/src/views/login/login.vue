<template>
  <div class="test">666</div>
</template>

<script setup lang="ts">
import { useUserStore } from '../../store/user'
const userStore = useUserStore()
console.log(userStore.name)
let i = 5
i = 6
</script>

<style lang="scss" scoped>
.test {
  background-color: $bg-color;
}
</style>
